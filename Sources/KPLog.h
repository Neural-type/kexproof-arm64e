#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Thread-safe log sink. Everything that lands here is:
//  - forwarded to NSLog with the [KexProof] prefix
//  - appended to an in-memory transcript (used for the report)
//  - pushed to the on-screen log view via the onAppend block (main queue)
@interface KPLog : NSObject

@property (nonatomic, copy, nullable) void (^onAppend)(NSString *text);

+ (instancetype)shared;

- (void)append:(NSString *)text;
- (void)appendFormat:(NSString *)fmt, ... NS_FORMAT_FUNCTION(1, 2);

// 1.5.3: transcript + UI only, no NSLog, no file write. Used by KPLogDirect,
// which already persisted the line to disk synchronously — routing it through
// -append as well would double-write the file and NSLog-echo every engine line.
- (void)appendTranscriptOnly:(NSString *)text;

// Full transcript so far. Ends with a newline when non-empty.
- (NSString *)transcript;

@end

// 1.5.1: C-callable bridge — pure-C code (XPF, exploit) can route a line through
// the full KPLog machinery (NSLog -> live stream AND the synced live file).
void KPLogNSLog(const char *line);

NS_ASSUME_NONNULL_END
