#
# This is loaded automatically at Zeek startup once the plugin gets activated
# and its BiF elements have become available. Include code here that should
# always execute unconditionally at that time.
#
# Note that this file is for plugin-level initialization code. The package's
# regular scripts should remain in the toplevel scripts folder.
#
module DelayedPcapSource;

export {
    ## Delay packets by so many seconds.
    const delay: interval = 0.0sec &redef;

    ## Fiddle the timestamp so many seconds into the past.
    const move_interval: interval = 0.0sec &redef;
}
