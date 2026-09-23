#import "KPAppDelegate.h"
#import "KPViewController.h"

@implementation KPAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    NSLog(@"[KexProof] didFinishLaunching");
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];

    KPViewController *main = [[KPViewController alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:main];

    UINavigationBarAppearance *appearance = [[UINavigationBarAppearance alloc] init];
    [appearance configureWithOpaqueBackground];
    appearance.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.09 alpha:1.0];
    appearance.titleTextAttributes = @{NSForegroundColorAttributeName: [UIColor whiteColor]};
    nav.navigationBar.standardAppearance = appearance;
    nav.navigationBar.scrollEdgeAppearance = appearance;

    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}

@end
