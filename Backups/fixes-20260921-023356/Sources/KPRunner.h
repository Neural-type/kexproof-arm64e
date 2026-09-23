#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Writes a line to the pre-capture stderr so KPLog can keep logging while
// stdout/stderr are piped (NSLog would recurse back into the pipe).
void KPForwardToOriginalStderr(NSString *line);

// Orchestrates one full pass: patchfind (XPF) -> exploit (ClearSword) ->
// guarded boot constants -> kernel dump -> report file.
@interface KPRunner : NSObject

// YES once gPrimitives.kreadbuf/kwritebuf are live.
@property (class, nonatomic, readonly) BOOL hasKRW;

// Runs everything on a background queue itself. Completion is called on the
// main queue; reportPath is nil when the pass failed before a report existed.
+ (void)runInBackgroundWithCompletion:(void (^)(BOOL success, NSString * _Nullable reportPath))completion;

@end

NS_ASSUME_NONNULL_END
