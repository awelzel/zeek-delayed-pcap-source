// See the file  in the main distribution directory for copyright.

#include "zeek/iosource/pcap/Source.h"

#include "zeek/zeek-config.h"

#ifdef HAVE_PCAP_INT_H
#include <pcap-int.h>
#endif

#include "zeek/Event.h"
#include "zeek/iosource/BPF_Program.h"
#include "zeek/iosource/Packet.h"
#include "zeek/iosource/pcap/pcap.bif.h"

#include "Source.h"
#include "delayedpcapsource.bif.h"

namespace
	{
double delay_remaining(const struct timeval* pkt_tv)
	{
	double to_delay = zeek::BifConst::DelayedPcapSource::delay;
	double now_ts = zeek::util::current_time(true);
	double pkt_ts = double(pkt_tv->tv_sec) + double(pkt_tv->tv_usec) / 1e6;
	return (pkt_ts + to_delay) - now_ts;
	}
	}

namespace zeek::iosource::delayedpcap
	{

PcapSource::~PcapSource()
	{
	Close();
	}

PcapSource::PcapSource(const std::string& path, bool is_live)
	{
	props.path = path;
	props.is_live = is_live;
	pd = nullptr;
	}

void PcapSource::Open()
	{
	if ( ! props.is_live )
		{
		Error("Only live interface supported");
		return;
		}

	OpenLive();
	}

void PcapSource::Close()
	{
	if ( ! pd )
		return;

	pcap_close(pd);
	pd = nullptr;

	Closed();

	if ( Pcap::file_done )
		event_mgr.Enqueue(Pcap::file_done, make_intrusive<StringVal>(props.path));
	}

double PcapSource::GetNextTimeout()
	{
	if ( ! pending_header )
		return -1;

	double ret = std::max(delay_remaining(&pending_header->ts), 0.0);
	return ret;
	}

void PcapSource::OpenLive()
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	// Determine interface if not specified.
	if ( props.path.empty() )
		{
		Error("No interface");
		return;
		}

	props.netmask = PktSrc::NETMASK_UNKNOWN;
	pd = pcap_create(props.path.c_str(), errbuf);
	if ( ! pd )
		{
		PcapError("pcap_create");
		return;
		}

	if ( pcap_set_snaplen(pd, BifConst::Pcap::snaplen) )
		{
		PcapError("pcap_set_snaplen");
		return;
		}

	if ( pcap_set_promisc(pd, 1) )
		{
		PcapError("pcap_set_promisc");
		return;
		}

	// We use the smallest time-out possible to return almost immediately
	// if no packets are available. (We can't use set_nonblocking() as
	// it's broken on FreeBSD: even when select() indicates that we can
	// read something, we may get nothing if the store buffer hasn't
	// filled up yet.)
	//
	// TODO: The comment about FreeBSD is pretty old and may not apply
	// anymore these days.
	if ( pcap_set_timeout(pd, 1) )
		{
		PcapError("pcap_set_timeout");
		return;
		}

	if ( pcap_set_buffer_size(pd, BifConst::Pcap::bufsize * 1024 * 1024) )
		{
		PcapError("pcap_set_buffer_size");
		return;
		}

	if ( pcap_activate(pd) )
		{
		PcapError("pcap_activate");
		return;
		}

#ifdef HAVE_LINUX
	if ( pcap_setnonblock(pd, 1, errbuf) < 0 )
		{
		PcapError("pcap_setnonblock");
		return;
		}
#endif

	// If we're delaying, we probably should use GetNextTimeout() exclusively.
	props.selectable_fd = pcap_get_selectable_fd(pd);

	props.link_type = pcap_datalink(pd);
	props.is_live = true;

	Opened(props);
	}

bool PcapSource::ExtractNextPacket(Packet* pkt)
	{
	if ( ! pd )
		return false;

	int res = -1;
	if ( pending_header )
		{
		// Treat this as successful pcap read, we check below
		// if it has been delayed enough.
		assert(pending_data);
		res = 1;
		}
	else
		res = pcap_next_ex(pd, &pending_header, &pending_data);

	switch ( res )
		{
		case PCAP_ERROR_BREAK: // -2
			// Exhausted pcap file, no more packets to read.
			assert(! props.is_live);
			Close();
			return false;
		case PCAP_ERROR: // -1
			// Error occurred while reading the packet.
			if ( props.is_live )
				reporter->Error("failed to read a packet from %s: %s", props.path.data(),
				                pcap_geterr(pd));
			else
				reporter->FatalError("failed to read a packet from %s: %s", props.path.data(),
				                     pcap_geterr(pd));
			return false;
		case 0:
			// Read from live interface timed out (ok).
			return false;
		case 1:
			// Read a packet without problem.
			// Although, some libpcaps may claim to have read a packet, but either did
			// not really read a packet or at least provide no way to access its
			// contents, so the following check for null-data helps handle those cases.
			if ( ! pending_data )
				{
				pending_header = nullptr;
				reporter->Weird("pcap_null_data_packet");
				return false;
				}
			break;
		default:
			reporter->InternalError("unhandled pcap_next_ex return value: %d", res);
			return false;
		}

	// Hard-core, we can probably fiddle with GetNextTimeout() instead
	// or use a different filedescriptor.
	if ( delay_remaining(&pending_header->ts) > 0.0 )
		{
		// std::fprintf(stderr, "Delaying more...\n");
		return false;
		}

	std::fprintf(stderr, "Allowing packet through...\n");

	double move_interval = zeek::BifConst::DelayedPcapSource::move_interval;
	double move_sec = static_cast<zeek_int_t>(move_interval);
	double move_usec = (move_interval - move_sec) * 1e6;

	pending_header->ts.tv_sec += move_sec;
	pending_header->ts.tv_usec += move_usec;

	pkt->Init(props.link_type, &pending_header->ts, pending_header->caplen, pending_header->len,
	          pending_data);

	if ( pending_header->len == 0 || pending_header->caplen == 0 )
		{
		Weird("empty_pcap_header", pkt);
		return false;
		}

	++stats.received;
	stats.bytes_received += pending_header->len;

	// Some versions of libpcap (myricom) are somewhat broken and will return a duplicate
	// packet if there are no more packets available. Namely, it returns the exact same
	// packet structure (including the header) out of the library without reinitializing
	// any of the values. If we set the header lengths to zero here, we can keep from
	// processing it a second time.
	pending_header->len = 0;
	pending_header->caplen = 0;

	return true;
	}

void PcapSource::DoneWithPacket()
	{
	pending_data = nullptr;
	pending_header = nullptr;
	}

bool PcapSource::PrecompileFilter(int index, const std::string& filter)
	{
	return PktSrc::PrecompileBPFFilter(index, filter);
	}

detail::BPF_Program* PcapSource::CompileFilter(const std::string& filter)
	{
	std::string errbuf;
	auto code = std::make_unique<detail::BPF_Program>();

	if ( ! code->Compile(pd, filter.c_str(), Netmask(), errbuf) )
		{
		std::string msg = util::fmt("cannot compile BPF filter \"%s\"", filter.c_str());

		if ( ! errbuf.empty() )
			msg += ": " + errbuf;

		Error(msg);
		return nullptr;
		}

	return code.release();
	}

bool PcapSource::SetFilter(int index)
	{
	if ( ! pd )
		return true; // Prevent error message

	char errbuf[PCAP_ERRBUF_SIZE];

	iosource::detail::BPF_Program* code = GetBPFFilter(index);

	if ( ! code )
		{
		snprintf(errbuf, sizeof(errbuf), "No precompiled pcap filter for index %d", index);
		Error(errbuf);
		return false;
		}

	if ( LinkType() == DLT_NFLOG )
		{
		// No-op, NFLOG does not support BPF filters.
		// Raising a warning might be good, but it would also be noisy
		// since the default scripts will always attempt to compile
		// and install a default filter
		}
	else
		{
		if ( pcap_setfilter(pd, code->GetProgram()) < 0 )
			{
			PcapError();
			return false;
			}
		}

#ifndef HAVE_LINUX
	// Linux doesn't clear counters when resetting filter.
	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
#endif

	return true;
	}

void PcapSource::Statistics(Stats* s)
	{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ( ! (props.is_live && pd) )
		s->received = s->dropped = s->link = s->bytes_received = 0;

	else
		{
		struct pcap_stat pstat;
		if ( pcap_stats(pd, &pstat) < 0 )
			{
			PcapError();
			s->received = s->dropped = s->link = s->bytes_received = 0;
			}

		else
			{
			s->dropped = pstat.ps_drop;
			s->link = pstat.ps_recv;
			}
		}

	s->received = stats.received;
	s->bytes_received = stats.bytes_received;

	if ( ! props.is_live )
		s->dropped = 0;
	}

void PcapSource::PcapError(const char* where)
	{
	std::string location;

	if ( where )
		location = util::fmt(" (%s)", where);

	if ( pd )
		Error(util::fmt("pcap_error: %s%s", pcap_geterr(pd), location.c_str()));
	else
		Error(util::fmt("pcap_error: not open%s", location.c_str()));

	Close();
	}

iosource::PktSrc* PcapSource::Instantiate(const std::string& path, bool is_live)
	{
	return new PcapSource(path, is_live);
	}

	} // namespace zeek::iosource::delayedpcap
