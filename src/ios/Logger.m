#import "Logger.h"
#import <Cordova/CDVPluginResult.h>
#import <Cordova/CDVCommandDelegate.h>

static BOOL g_debugEnabled = NO;
static BOOL g_initialised = NO;
static __weak id g_commandDelegate = nil;
static NSString *g_callbackId = nil;
static const NSTimeInterval kNativeLogCallbackTimeout = 10.0;
static NSMutableArray<NSDictionary *> *g_bufferedMessages = nil;
static dispatch_block_t g_callbackTimeoutBlock = nil;
static BOOL g_bufferingEnabled = YES;

@interface Logger ()
+ (void)sendPayload:(NSDictionary *)payload;
+ (void)expireBufferedMessages;
@end

@implementation Logger

+ (void)load
{
    g_bufferedMessages = [[NSMutableArray alloc] init];
    g_callbackTimeoutBlock = dispatch_block_create(0, ^{
        [Logger expireBufferedMessages];
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kNativeLogCallbackTimeout * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), g_callbackTimeoutBlock);
}

+ (void)registerCommandDelegate:(id)commandDelegate callbackId:(NSString *)callbackId
{
    NSArray<NSDictionary *> *bufferedMessages;
    @synchronized(self) {
        g_commandDelegate = commandDelegate;
        g_callbackId = [callbackId copy];
        bufferedMessages = [g_bufferedMessages copy];
        [g_bufferedMessages removeAllObjects];
        if (g_bufferingEnabled) {
            g_bufferingEnabled = NO;
            dispatch_block_cancel(g_callbackTimeoutBlock);
            g_callbackTimeoutBlock = nil;
        }
    }
    for (NSDictionary *payload in bufferedMessages) {
        [self sendPayload:payload];
    }
    [self sendLevel:CdvPurchaseLoggerLevelInfo format:@"Native log listener registered"];
}

+ (void)clearCommandDelegate
{
    g_commandDelegate = nil;
    g_callbackId = nil;
}

+ (void)setDebugEnabled:(BOOL)enabled
{
    g_debugEnabled = enabled;
}

+ (void)setInitialised:(BOOL)initialised
{
    g_initialised = initialised;
}

+ (void)debug:(NSString *)format, ...
{
    va_list arguments;
    va_start(arguments, format);
    [self sendLevel:CdvPurchaseLoggerLevelDebug format:format arguments:arguments];
    va_end(arguments);
}

+ (void)info:(NSString *)format, ...
{
    va_list arguments;
    va_start(arguments, format);
    [self sendLevel:CdvPurchaseLoggerLevelInfo format:format arguments:arguments];
    va_end(arguments);
}

+ (void)warning:(NSString *)format, ...
{
    va_list arguments;
    va_start(arguments, format);
    [self sendLevel:CdvPurchaseLoggerLevelWarning format:format arguments:arguments];
    va_end(arguments);
}

+ (void)error:(NSString *)format, ...
{
    va_list arguments;
    va_start(arguments, format);
    [self sendLevel:CdvPurchaseLoggerLevelError format:format arguments:arguments];
    va_end(arguments);
}

+ (void)sendLevel:(CdvPurchaseLoggerLevel)level format:(NSString *)format, ...
{
    va_list arguments;
    va_start(arguments, format);
    [self sendLevel:level format:format arguments:arguments];
    va_end(arguments);
}

+ (void)sendLevel:(CdvPurchaseLoggerLevel)level format:(NSString *)format arguments:(va_list)arguments
{
    NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
    NSString *levelString = @[@"debug", @"info", @"warning", @"error"][(NSUInteger)level];
    NSString *formattedMessage = [NSString stringWithFormat:@"[CdvPurchase.AppleAppStore.objc] %@: %@", levelString, message];

    if (level != CdvPurchaseLoggerLevelDebug || g_debugEnabled || !g_initialised) {
        NSLog(@"%@", formattedMessage);
    }

    NSDictionary *payload = @{
        @"level": levelString,
        @"message": formattedMessage,
    };
    [self sendPayload:payload];
}

+ (void)sendPayload:(NSDictionary *)payload
{
    id commandDelegate;
    NSString *callbackId;
    @synchronized(self) {
        commandDelegate = g_commandDelegate;
        callbackId = [g_callbackId copy];
        if (!commandDelegate || !callbackId) {
            if (g_bufferingEnabled) {
                [g_bufferedMessages addObject:payload];
            }
            return;
        }
    }
    CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:payload];
    [result setKeepCallbackAsBool:YES];
    dispatch_async(dispatch_get_main_queue(), ^{
        [commandDelegate sendPluginResult:result callbackId:callbackId];
    });
}

+ (void)expireBufferedMessages
{
    @synchronized(self) {
        if (!g_bufferingEnabled) return;
        g_bufferingEnabled = NO;
        [g_bufferedMessages removeAllObjects];
        g_callbackTimeoutBlock = nil;
    }
    [self warning:@"Native log listener was not registered within %.0f seconds; buffered messages were discarded",
                 kNativeLogCallbackTimeout];
}

@end
