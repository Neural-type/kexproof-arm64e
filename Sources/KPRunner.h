#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Writes a line to the pre-capture stderr so KPLog can keep logging while
// stdout/stderr are piped (NSLog would recurse back into the pipe).
void KPForwardToOriginalStderr(NSString *line);

// Orchestrates the run. 1.5.9: split at the win line — stages 1-3 (XPF,
// exploit, boot constants) are one job; stage 4 (the long dump) is a separate
// button, so a panic mid-dump no longer burns the exploit's win.
@interface KPRunner : NSObject

// YES once gPrimitives.kreadbuf/kwritebuf are live.
@property (class, nonatomic, readonly) BOOL hasKRW;

// Stages 1-3 on a background queue. Completion on the main queue.
+ (void)runExploitWithCompletion:(void (^)(BOOL success))completion;

// Stage 4 (kernel dump) on a background queue. Requires hasKRW. Completion on
// the main queue; reportPath is nil when the dump failed before a report
// existed.
+ (void)runDumpWithCompletion:(void (^)(BOOL success, NSString * _Nullable reportPath))completion;

@end

NS_ASSUME_NONNULL_END
