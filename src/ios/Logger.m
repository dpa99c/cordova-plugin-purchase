#import "Logger.h"
#import <Cordova/CDVPluginResult.h>
#import <Cordova/CDVCommandDelegate.h>

static BOOL g_debugEnabled = NO;
static BOOL g_initialised = NO;
static __weak id g_commandDelegate = nil;
static NSString *g_callbackId = nil;

@implementation Logger

+ (void)registerCommandDelegate:(id)commandDelegate callbackId:(NSString *)callbackId
{
    g_commandDelegate = commandDelegate;
    g_callbackId = [callbackId copy];
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

    id commandDelegate = g_commandDelegate;
    NSString *callbackId = g_callbackId;
    if (!commandDelegate || !callbackId) return;

    NSDictionary *payload = @{
        @"level": levelString,
        @"message": formattedMessage,
    };
    CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:payload];
    [result setKeepCallbackAsBool:YES];
    dispatch_async(dispatch_get_main_queue(), ^{
        [commandDelegate sendPluginResult:result callbackId:callbackId];
    });
}

@end
