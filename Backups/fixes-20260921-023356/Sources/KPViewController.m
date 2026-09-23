#import "KPViewController.h"
#import "KPLog.h"
#import "KPRunner.h"
#import "KPDump.h"

#import <unistd.h>

@interface KPViewController ()
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIButton *exploitButton;
@property (nonatomic, strong) UIButton *sptmButton;
@property (nonatomic, strong) UIButton *sptmTableButton;
@property (nonatomic, strong) UIButton *surveyButton;
@property (nonatomic, strong) UIButton *rootButton;
@property (nonatomic, strong) UIButton *shareButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, copy, nullable) NSString *reportPath;
@end

@implementation KPViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSLog(@"[KexProof] screen: main");
    self.title = @"KexProof";
    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.09 alpha:1.0];

    UILabel *titleLabel = [self makeLabel:28 weight:UIFontWeightBold color:[UIColor whiteColor]];
    titleLabel.text = @"KexProof";
    titleLabel.textAlignment = NSTextAlignmentCenter;

    UILabel *subtitle = [self makeLabel:13 weight:UIFontWeightRegular color:[UIColor colorWithRed:0.55 green:0.85 blue:0.65 alpha:1.0]];
    subtitle.text = @"CVE-2025-43520 · ClearSword · дамп SPTM/TXM · 1.5.4";
    subtitle.textAlignment = NSTextAlignmentCenter;

    self.statusLabel = [self makeLabel:13 weight:UIFontWeightSemibold color:[UIColor secondaryLabelColor]];
    self.statusLabel.text = @"Готов. Нажмите «Запустить эксплойт».";
    self.statusLabel.textAlignment = NSTextAlignmentCenter;

    self.logView = [[UITextView alloc] init];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor colorWithRed:0.03 green:0.03 blue:0.04 alpha:1.0];
    self.logView.textColor = [UIColor colorWithRed:0.75 green:0.95 blue:0.75 alpha:1.0];
    self.logView.layer.cornerRadius = 10;
    self.logView.layer.borderWidth = 1;
    self.logView.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.15].CGColor;
    self.logView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    self.logView.text = @"";

    self.exploitButton = [self makeButton:@"Запустить эксплойт"
                                    color:[UIColor colorWithRed:0.20 green:0.55 blue:0.35 alpha:1.0]];
    [self.exploitButton addTarget:self action:@selector(exploitTapped) forControlEvents:UIControlEventTouchUpInside];

    self.sptmButton = [self makeButton:@"A0: тест записи (безопасно)"
                                 color:[UIColor colorWithRed:0.55 green:0.35 blue:0.60 alpha:1.0]];
    [self.sptmButton addTarget:self action:@selector(sptmTapped) forControlEvents:UIControlEventTouchUpInside];

    self.sptmTableButton = [self makeButton:@"A1: frame_table (МОЖЕТ РЕБУТНУТЬ)"
                                      color:[UIColor colorWithRed:0.70 green:0.22 blue:0.22 alpha:1.0]];
    [self.sptmTableButton addTarget:self action:@selector(sptmTableTapped) forControlEvents:UIControlEventTouchUpInside];

    self.surveyButton = [self makeButton:@"E1–E3: обзор SPTM (read-only)"
                                   color:[UIColor colorWithRed:0.20 green:0.45 blue:0.55 alpha:1.0]];
    [self.surveyButton addTarget:self action:@selector(surveyTapped) forControlEvents:UIControlEventTouchUpInside];

    self.rootButton = [self makeButton:@"E9: root через кучу (ucred swap)"
                                 color:[UIColor colorWithRed:0.72 green:0.45 blue:0.15 alpha:1.0]];
    [self.rootButton addTarget:self action:@selector(rootTapped) forControlEvents:UIControlEventTouchUpInside];

    self.shareButton = [self makeButton:@"Поделиться отчётом"
                                  color:[UIColor colorWithRed:0.25 green:0.35 blue:0.60 alpha:1.0]];
    [self.shareButton addTarget:self action:@selector(shareTapped) forControlEvents:UIControlEventTouchUpInside];
    // Always tappable: it shares the report if present AND the live log, so a
    // panic before any dump still leaves something to send back.
    self.shareButton.enabled = YES;
    self.shareButton.alpha = 1.0;

    [self updateExperimentButtons];

    [self.view addSubview:titleLabel];
    [self.view addSubview:subtitle];
    [self.view addSubview:self.statusLabel];
    [self.view addSubview:self.logView];
    [self.view addSubview:self.exploitButton];
    [self.view addSubview:self.sptmButton];
    [self.view addSubview:self.sptmTableButton];
    [self.view addSubview:self.surveyButton];
    [self.view addSubview:self.rootButton];
    [self.view addSubview:self.shareButton];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [titleLabel.topAnchor constraintEqualToAnchor:safe.topAnchor constant:10],
        [titleLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [titleLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [subtitle.topAnchor constraintEqualToAnchor:titleLabel.bottomAnchor constant:2],
        [subtitle.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [subtitle.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [self.statusLabel.topAnchor constraintEqualToAnchor:subtitle.bottomAnchor constant:8],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [self.logView.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:8],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.logView.bottomAnchor constraintEqualToAnchor:self.exploitButton.topAnchor constant:-10],

        [self.exploitButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.exploitButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.exploitButton.heightAnchor constraintEqualToConstant:46],
        [self.exploitButton.bottomAnchor constraintEqualToAnchor:self.sptmButton.topAnchor constant:-8],

        [self.sptmButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.sptmButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.sptmButton.heightAnchor constraintEqualToConstant:38],
        [self.sptmButton.bottomAnchor constraintEqualToAnchor:self.sptmTableButton.topAnchor constant:-7],

        [self.sptmTableButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.sptmTableButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.sptmTableButton.heightAnchor constraintEqualToConstant:38],
        [self.sptmTableButton.bottomAnchor constraintEqualToAnchor:self.surveyButton.topAnchor constant:-7],

        [self.surveyButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.surveyButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.surveyButton.heightAnchor constraintEqualToConstant:38],
        [self.surveyButton.bottomAnchor constraintEqualToAnchor:self.rootButton.topAnchor constant:-7],

        [self.rootButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.rootButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.rootButton.heightAnchor constraintEqualToConstant:38],
        [self.rootButton.bottomAnchor constraintEqualToAnchor:self.shareButton.topAnchor constant:-8],

        [self.shareButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.shareButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.shareButton.heightAnchor constraintEqualToConstant:40],
        [self.shareButton.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-10],
    ]];

    __weak typeof(self) weakSelf = self;
    [KPLog shared].onAppend = ^(NSString *text) {
        [weakSelf appendLogText:text];
    };

    [[KPLog shared] appendFormat:@"=== запуск KexProof %@ @ %@ ===",
        [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"], [NSDate date]];
    [[KPLog shared] append:@"KexProof загружен. Эксплойт работает в обычной песочнице приложения, без джейлбрейк-энтитлментов."];
}

- (UILabel *)makeLabel:(CGFloat)size weight:(UIFontWeight)weight color:(UIColor *)color {
    UILabel *label = [[UILabel alloc] init];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.font = [UIFont systemFontOfSize:size weight:weight];
    label.textColor = color;
    label.numberOfLines = 0;
    return label;
}

- (UIButton *)makeButton:(NSString *)title color:(UIColor *)color {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    button.backgroundColor = color;
    button.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    button.layer.cornerRadius = 10;
    button.clipsToBounds = YES;
    return button;
}

- (void)setExperimentButton:(UIButton *)button enabled:(BOOL)enabled {
    button.enabled = enabled;
    button.alpha = enabled ? 1.0 : 0.45;
}

- (void)updateExperimentButtons {
    BOOL krw = KPRunner.hasKRW;
    [self setExperimentButton:self.sptmButton enabled:krw];
    [self setExperimentButton:self.sptmTableButton enabled:krw];
    [self setExperimentButton:self.surveyButton enabled:krw];
    [self setExperimentButton:self.rootButton enabled:krw];
}

- (void)appendLogText:(NSString *)text {
    self.logView.text = [self.logView.text stringByAppendingString:text];
    if (self.logView.text.length > 0) {
        NSRange end = NSMakeRange(self.logView.text.length - 1, 1);
        [self.logView scrollRangeToVisible:end];
    }
}

// Writes an experiment report to Documents and points the share button at it.
- (void)saveExperimentReport:(NSString *)text fileName:(NSString *)fileName {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *path = [docs stringByAppendingPathComponent:fileName];
    NSString *full = [text stringByAppendingFormat:@"\n\n--- Полный журнал ---\n%@", [KPLog shared].transcript];
    NSError *error = nil;
    if ([full writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        self.reportPath = path;
        self.shareButton.enabled = YES;
        self.shareButton.alpha = 1.0;
        [[KPLog shared] appendFormat:@"Отчёт записан: %@", path];
    }
    else {
        [[KPLog shared] appendFormat:@"Не удалось записать %@: %@", fileName, error];
    }
}

- (void)exploitTapped {
    self.exploitButton.enabled = NO;
    self.exploitButton.alpha = 0.45;
    self.statusLabel.text = @"Выполняется… (эксплойт может идти несколько минут)";

    [KPRunner runInBackgroundWithCompletion:^(BOOL success, NSString *reportPath) {
        if (success && reportPath) {
            self.reportPath = reportPath;
            self.statusLabel.text = @"Готово. Отчёт: Documents/kexproof-dump.txt";
            self.shareButton.enabled = YES;
            self.shareButton.alpha = 1.0;
            [self.exploitButton setTitle:@"Повторить дамп" forState:UIControlStateNormal];
        }
        else if (KPRunner.hasKRW) {
            self.statusLabel.text = @"KRW активен, но отчёт не записался. Можно повторить.";
            [self.exploitButton setTitle:@"Повторить дамп" forState:UIControlStateNormal];
        }
        else {
            self.statusLabel.text = @"Эксплойт не удался. Можно повторить.";
            [self.exploitButton setTitle:@"Повторить эксплойт" forState:UIControlStateNormal];
        }
        [self updateExperimentButtons];
        self.exploitButton.enabled = YES;
        self.exploitButton.alpha = 1.0;
    }];
}

- (void)sptmTapped {
    if (!KPRunner.hasKRW) return;
    [self setExperimentButton:self.sptmButton enabled:NO];
    self.statusLabel.text = @"A0: тест записи (безопасно)…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPDump sptmWriteTestReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.statusLabel.text = @"A0 завершён — см. лог";
            [self setExperimentButton:self.sptmButton enabled:YES];
            [self appendLogText:report];
        });
    });
}

- (void)sptmTableTapped {
    if (!KPRunner.hasKRW) return;
    [self setExperimentButton:self.sptmTableButton enabled:NO];
    self.statusLabel.text = @"A1: frame_table… (может ребутнуть!)";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPDump sptmFrameTableWriteTestReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.statusLabel.text = @"A1 завершён — см. лог";
            [self setExperimentButton:self.sptmTableButton enabled:YES];
            [self appendLogText:report];
        });
    });
}

- (void)surveyTapped {
    if (!KPRunner.hasKRW) return;
    [self setExperimentButton:self.surveyButton enabled:NO];
    self.statusLabel.text = @"E1–E3: обзор SPTM… (read-only)";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *survey = [KPDump sptmSurveyReport];
        // Refresh the main dump too: it now embeds the fixed allproc (EXP-01)
        // and the harvested SPTM/TXM bases (EXP-02).
        NSString *dump = [KPDump buildReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.statusLabel.text = @"E1–E3 завершены — см. лог";
            [self setExperimentButton:self.surveyButton enabled:YES];
            [self appendLogText:survey];
            [self saveExperimentReport:survey fileName:@"kexproof-e1e3-survey.txt"];
            NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            [dump writeToFile:[docs stringByAppendingPathComponent:@"kexproof-dump.txt"]
                   atomically:YES encoding:NSUTF8StringEncoding error:nil];
        });
    });
}

- (void)rootTapped {
    if (!KPRunner.hasKRW) return;
    UIAlertController *confirm = [UIAlertController
        alertControllerWithTitle:@"E9: ucred swap"
        message:@"Одна 8-байтная heap-запись: proc_ro->p_ucred → форг в pipe-буфере (uid/gid 0, label очищен). Форг не освобождается, оригинал логируется. Малый риск паники. Продолжить?"
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [confirm addAction:[UIAlertAction actionWithTitle:@"Выполнить" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [weakSelf runRootSwap];
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

- (void)runRootSwap {
    [self setExperimentButton:self.rootButton enabled:NO];
    self.statusLabel.text = @"E9: подмена p_ucred…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPDump ucredHeapSwapReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            BOOL root = (getuid() == 0);
            self.statusLabel.text = root ? @"E9 PASS: uid 0 (root) — см. лог" : @"E9 завершён — см. лог";
            [self setExperimentButton:self.rootButton enabled:YES];
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-e9-ucred.txt"];
        });
    });
}

- (void)shareTapped {
    NSMutableArray *items = [NSMutableArray array];
    if (self.reportPath) {
        [items addObject:[NSURL fileURLWithPath:self.reportPath]];
    }
    NSString *live = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-live.log"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:live]) {
        [items addObject:[NSURL fileURLWithPath:live]];
    }
    // 1.2.2: previous session's log (survives reboots via rotation) — the file
    // that actually matters after a panic.
    NSString *prev = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-prev.log"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:prev]) {
        [items addObject:[NSURL fileURLWithPath:prev]];
    }
    if (items.count == 0) {
        self.statusLabel.text = @"Пока нечем делиться (ни отчёта, ни live-лога)";
        return;
    }
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];
    activity.popoverPresentationController.sourceView = self.shareButton;
    [self presentViewController:activity animated:YES completion:nil];
}

@end
