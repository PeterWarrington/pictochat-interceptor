#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

static int fail(NSString *message) {
    fprintf(stderr, "%s\n", message.UTF8String);
    return 1;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 3) {
            return fail(@"usage: macos_wifi_channel <interface> <channel>");
        }

        NSString *interfaceName = [NSString stringWithUTF8String:argv[1]];
        NSInteger requestedChannel = [[NSString stringWithUTF8String:argv[2]] integerValue];
        CWInterface *interface = [[CWWiFiClient sharedWiFiClient] interfaceWithName:interfaceName];
        if (interface == nil) {
            return fail([NSString stringWithFormat:
                @"CoreWLAN could not open Wi-Fi interface %@", interfaceName]);
        }

        CWChannel *selectedChannel = nil;
        for (CWChannel *channel in interface.supportedWLANChannels) {
            if (channel.channelNumber == requestedChannel &&
                channel.channelBand == kCWChannelBand2GHz &&
                channel.channelWidth == kCWChannelWidth20MHz) {
                selectedChannel = channel;
                break;
            }
        }
        if (selectedChannel == nil) {
            return fail([NSString stringWithFormat:
                @"Wi-Fi channel %ld at 2.4 GHz/20 MHz is not supported",
                (long)requestedChannel]);
        }

        [interface disassociate];
        [NSThread sleepForTimeInterval:0.4];

        NSError *error = nil;
        if (![interface setWLANChannel:selectedChannel error:&error]) {
            return fail([NSString stringWithFormat:
                @"CoreWLAN could not set channel %ld: %@",
                (long)requestedChannel, error.localizedDescription]);
        }

        NSInteger actualChannel = interface.wlanChannel.channelNumber;
        if (actualChannel != requestedChannel) {
            return fail([NSString stringWithFormat:
                @"CoreWLAN requested channel %ld, but the interface reports channel %ld",
                (long)requestedChannel, (long)actualChannel]);
        }

        printf("CHANNEL=%ld\n", (long)actualChannel);
        return 0;
    }
}
