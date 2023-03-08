#include "Plugin.h"

#include "zeek/iosource/Component.h"

#include "Source.h"
#include "config.h"

namespace zeek::plugin::Zeek_DelayedPcapSource
	{
Plugin plugin;
	}

using namespace zeek::plugin::Zeek_DelayedPcapSource;

zeek::plugin::Configuration Plugin::Configure()
	{

	AddComponent(new iosource::PktSrcComponent(
		"DelayedPcapReader", "delayedpcap", iosource::PktSrcComponent::LIVE,
		zeek::iosource::delayedpcap::PcapSource::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Zeek::DelayedPcapSource";
	config.description = "Delay network packets arbitrarily.";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
