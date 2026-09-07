#import <Foundation/Foundation.h>

/** Native log levels exposed to the JavaScript bridge. */
typedef NS_ENUM(NSInteger, CdvPurchaseLoggerLevel) {
    CdvPurchaseLoggerLevelDebug,
    CdvPurchaseLoggerLevelInfo,
    CdvPurchaseLoggerLevelWarning,
    CdvPurchaseLoggerLevelError,
};

/** Centralised native logger for the purchase plugin. */
@interface Logger : NSObject

/** Register the Cordova callback that receives native log messages. */
+ (void)registerCommandDelegate:(id)commandDelegate callbackId:(NSString *)callbackId;

/** Remove the registered Cordova log callback. */
+ (void)clearCommandDelegate;

/** Enable verbose native console output. */
+ (void)setDebugEnabled:(BOOL)enabled;

/** Mark the plugin as initialised for console output gating. */
+ (void)setInitialised:(BOOL)initialised;

/** Emit a debug message. */
+ (void)debug:(NSString *)format, ...;

/** Emit an informational message. */
+ (void)info:(NSString *)format, ...;

/** Emit a warning message. */
+ (void)warning:(NSString *)format, ...;

/** Emit an error message. */
+ (void)error:(NSString *)format, ...;

@end
