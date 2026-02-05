#include <pjsua2.hpp>
#include <pjsip.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace pj;

namespace {
std::atomic<bool> g_shutdown{false};

void handle_signal(int) {
    g_shutdown = true;
}

struct Args {
    std::string sip_uri;
    std::string meeting_id;
    std::string local_id;
    std::string display_name;
    std::string auth_user;
    std::string auth_pass;
    std::string auth_realm = "*";
    std::string transport = "udp";
    std::string outbound_proxy;
    std::string registrar_uri;
    std::string registrar_ip;
    std::string contact_forced;
    bool force_sips_contact = false;
    bool register_on_add = false;
    bool wait_for_register = false;
    bool register_optional = false;
    std::vector<std::string> nameservers;
    bool disable_secure_dlg_check = false;
    bool prefer_opus = true;
    int stats_interval_sec = 5;
    int sip_keepalive_sec = 30;
    std::string record_file;
    std::string config_path;
    int log_level = 4;
    int max_seconds = 300;
    bool enable_video = true;
    bool null_audio = true;
};

void print_usage(const char* argv0) {
    std::cout << "Usage: " << argv0
              << " --sip-uri <sip:...> --local-id <sip:...> [options]\n"
              << "Options:\n"
              << "  --meeting-id <number>\n"
              << "  --display-name <name>\n"
              << "  --auth-user <user>\n"
              << "  --auth-pass <pass>\n"
              << "  --auth-realm <realm>\n"
              << "  --transport <udp|tcp|tls>\n"
              << "  --outbound-proxy <sip:proxy;transport=udp>\n"
              << "  --registrar-uri <sips:registrar;transport=tls>\n"
              << "  --registrar-ip <ip>\n"
              << "  --contact-forced <sip:USER@HOST:PORT;transport=tls>\n"
              << "  --force-sips-contact\n"
              << "  --register\n"
              << "  --wait-for-register\n"
              << "  --register-optional\n"
              << "  --nameserver <ip>\n"
              << "  --no-default-nameserver\n"
              << "  --disable-secure-dlg-check\n"
              << "  --no-prefer-opus\n"
              << "  --stats-interval <sec>\n"
              << "  --sip-keepalive <sec>\n"
              << "  --record-file <path.wav>\n"
              << "  --config <path>\n"
              << "  --log-level <0-6>\n"
              << "  --max-seconds <n>\n"
              << "  --no-video\n"
              << "  --no-null-audio\n";
}

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static bool parse_bool(const std::string& v, bool& out) {
    std::string val = v;
    for (auto& c : val) c = static_cast<char>(::tolower(c));
    if (val == "1" || val == "true" || val == "yes" || val == "on") {
        out = true;
        return true;
    }
    if (val == "0" || val == "false" || val == "no" || val == "off") {
        out = false;
        return true;
    }
    return false;
}

static void split_csv(const std::string& s, std::vector<std::string>& out) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        auto t = trim(item);
        if (!t.empty()) out.push_back(t);
    }
}

static bool load_config_file(const std::string& path, Args& out) {
    std::ifstream in(path);
    if (!in.is_open()) {
        std::cerr << "Failed to open config file: " << path << "\n";
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        auto t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        auto eq = t.find('=');
        if (eq == std::string::npos) continue;
        auto key = trim(t.substr(0, eq));
        auto val = trim(t.substr(eq + 1));

        if (key == "sip_uri") out.sip_uri = val;
        else if (key == "meeting_id") out.meeting_id = val;
        else if (key == "local_id") out.local_id = val;
        else if (key == "display_name") out.display_name = val;
        else if (key == "auth_user") out.auth_user = val;
        else if (key == "auth_pass") out.auth_pass = val;
        else if (key == "auth_realm") out.auth_realm = val;
        else if (key == "transport") out.transport = val;
        else if (key == "outbound_proxy") out.outbound_proxy = val;
        else if (key == "registrar_uri") out.registrar_uri = val;
        else if (key == "registrar_ip") out.registrar_ip = val;
        else if (key == "contact_forced") out.contact_forced = val;
        else if (key == "record_file") out.record_file = val;
        else if (key == "nameserver") {
            out.nameservers.clear();
            split_csv(val, out.nameservers);
        } else if (key == "stats_interval") out.stats_interval_sec = std::stoi(val);
        else if (key == "sip_keepalive") out.sip_keepalive_sec = std::stoi(val);
        else if (key == "log_level") out.log_level = std::stoi(val);
        else if (key == "max_seconds") out.max_seconds = std::stoi(val);
        else if (key == "force_sips_contact") parse_bool(val, out.force_sips_contact);
        else if (key == "register") parse_bool(val, out.register_on_add);
        else if (key == "wait_for_register") parse_bool(val, out.wait_for_register);
        else if (key == "register_optional") parse_bool(val, out.register_optional);
        else if (key == "disable_secure_dlg_check") parse_bool(val, out.disable_secure_dlg_check);
        else if (key == "prefer_opus") parse_bool(val, out.prefer_opus);
        else if (key == "enable_video") parse_bool(val, out.enable_video);
        else if (key == "null_audio") parse_bool(val, out.null_audio);
    }
    return true;
}

bool parse_args(int argc, char** argv, Args& out) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto need_value = [&](std::string& dst) -> bool {
            if (i + 1 >= argc) return false;
            dst = argv[++i];
            return true;
        };
        if (arg == "--sip-uri") {
            if (!need_value(out.sip_uri)) return false;
        } else if (arg == "--meeting-id") {
            if (!need_value(out.meeting_id)) return false;
        } else if (arg == "--local-id") {
            if (!need_value(out.local_id)) return false;
        } else if (arg == "--display-name") {
            if (!need_value(out.display_name)) return false;
        } else if (arg == "--auth-user") {
            if (!need_value(out.auth_user)) return false;
        } else if (arg == "--auth-pass") {
            if (!need_value(out.auth_pass)) return false;
        } else if (arg == "--auth-realm") {
            if (!need_value(out.auth_realm)) return false;
        } else if (arg == "--transport") {
            if (!need_value(out.transport)) return false;
        } else if (arg == "--outbound-proxy") {
            if (!need_value(out.outbound_proxy)) return false;
        } else if (arg == "--registrar-uri") {
            if (!need_value(out.registrar_uri)) return false;
        } else if (arg == "--registrar-ip") {
            if (!need_value(out.registrar_ip)) return false;
        } else if (arg == "--contact-forced") {
            if (!need_value(out.contact_forced)) return false;
        } else if (arg == "--force-sips-contact") {
            out.force_sips_contact = true;
        } else if (arg == "--register") {
            out.register_on_add = true;
        } else if (arg == "--wait-for-register") {
            out.wait_for_register = true;
        } else if (arg == "--register-optional") {
            out.register_optional = true;
        } else if (arg == "--nameserver") {
            std::string ns;
            if (!need_value(ns)) return false;
            out.nameservers.push_back(ns);
        } else if (arg == "--no-default-nameserver") {
            out.nameservers.clear();
        } else if (arg == "--disable-secure-dlg-check") {
            out.disable_secure_dlg_check = true;
        } else if (arg == "--no-prefer-opus") {
            out.prefer_opus = false;
        } else if (arg == "--stats-interval") {
            std::string v;
            if (!need_value(v)) return false;
            out.stats_interval_sec = std::stoi(v);
        } else if (arg == "--sip-keepalive") {
            std::string v;
            if (!need_value(v)) return false;
            out.sip_keepalive_sec = std::stoi(v);
        } else if (arg == "--record-file") {
            if (!need_value(out.record_file)) return false;
        } else if (arg == "--config") {
            if (!need_value(out.config_path)) return false;
        } else if (arg == "--log-level") {
            std::string v;
            if (!need_value(v)) return false;
            out.log_level = std::stoi(v);
        } else if (arg == "--max-seconds") {
            std::string v;
            if (!need_value(v)) return false;
            out.max_seconds = std::stoi(v);
        } else if (arg == "--no-video") {
            out.enable_video = false;
        } else if (arg == "--no-null-audio") {
            out.null_audio = false;
        } else if (arg == "--help" || arg == "-h") {
            return false;
        } else {
            std::cerr << "Unknown arg: " << arg << "\n";
            return false;
        }
    }

    if (out.sip_uri.empty() && !out.meeting_id.empty()) {
        out.sip_uri = "sips:" + out.meeting_id + "@meet.webex.com";
    }

    if (out.sip_uri.empty() || out.local_id.empty()) {
        return false;
    }

    return true;
}

class SmokeCall : public Call {
public:
    explicit SmokeCall(Account& acc) : Call(acc) {}

    void onCallState(OnCallStateParam&) override {
        CallInfo ci = getInfo();
        std::cout << "Call state: " << ci.stateText
                  << " (" << ci.lastStatusCode << " " << ci.lastReason << ")\n";
        if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
            confirmed = true;
            confirmed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               std::chrono::steady_clock::now().time_since_epoch())
                               .count();
        }
        if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
            disconnected = true;
        }
    }

    void onCallMediaState(OnCallMediaStateParam&) override {
        CallInfo ci = getInfo();
        for (const auto& media : ci.media) {
            if (media.type == PJMEDIA_TYPE_AUDIO) {
                std::cout << "Audio media status: " << media.status << "\n";
            } else if (media.type == PJMEDIA_TYPE_VIDEO) {
                std::cout << "Video media status: " << media.status << "\n";
            }
        }
    }

    std::atomic<bool> disconnected{false};
    std::atomic<bool> confirmed{false};
    std::atomic<long long> confirmed_ns{0};
};

class SmokeAccount : public Account {
public:
    void onRegState(OnRegStateParam&) override {
        AccountInfo ai = getInfo();
        std::cout << "Registration status: " << ai.regStatus
                  << " (" << ai.regStatusText << ")\n";
    }
};

}  // namespace

static void print_audio_stats(Call& call) {
    try {
        CallInfo ci = call.getInfo();
        for (size_t i = 0; i < ci.media.size(); ++i) {
            const auto& media = ci.media[i];
            if (media.type != PJMEDIA_TYPE_AUDIO) continue;
            if (media.status != PJSUA_CALL_MEDIA_ACTIVE) continue;

            StreamInfo si = call.getStreamInfo(static_cast<unsigned>(i));
            StreamStat st = call.getStreamStat(static_cast<unsigned>(i));

            const auto& rx = st.rtcp.rxStat;
            const auto& tx = st.rtcp.txStat;

            std::cout << "RTP audio stats: "
                      << si.codecName << " "
                      << "rx_pkts=" << rx.pkt
                      << " rx_lost=" << rx.loss
                      << " rx_jitter_ms=" << std::fixed << std::setprecision(2)
                      << (rx.jitterUsec.mean / 1000.0)
                      << " tx_pkts=" << tx.pkt
                      << " tx_lost=" << tx.loss
                      << " tx_jitter_ms=" << (tx.jitterUsec.mean / 1000.0)
                      << "\n";
            return;
        }
    } catch (Error&) {
        std::cout << "RTP audio stats: unavailable\n";
    }
}

int main(int argc, char** argv) {
    Args args;
    // Pre-scan for config path
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--config" && i + 1 < argc) {
            args.config_path = argv[i + 1];
            break;
        }
    }
    if (!args.config_path.empty()) {
        load_config_file(args.config_path, args);
    }
    if (!parse_args(argc, argv, args)) {
        print_usage(argv[0]);
        return 2;
    }
    if (args.record_file.empty()) {
        args.record_file = "webex_audio.wav";
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    Endpoint ep;
    ep.libCreate();

    EpConfig ep_cfg;
    ep_cfg.logConfig.level = args.log_level;
    ep_cfg.logConfig.consoleLevel = args.log_level;
    ep_cfg.uaConfig.userAgent = "janus-cpp-sip-smoke";
    ep_cfg.medConfig.vidPreviewEnableNative = false;
    if (args.nameservers.empty()) {
        ep_cfg.uaConfig.nameserver.push_back("8.8.8.8");
        ep_cfg.uaConfig.nameserver.push_back("1.1.1.1");
    } else {
        for (const auto& ns : args.nameservers) {
            ep_cfg.uaConfig.nameserver.push_back(ns);
        }
    }

    ep.libInit(ep_cfg);

    if (args.disable_secure_dlg_check) {
        pjsip_cfg()->endpt.disable_secure_dlg_check = PJ_TRUE;
        std::cerr << "Warning: secure dialog check disabled (SIPS required enforcement off)\n";
    }

    TransportConfig tcfg;
    tcfg.port = 0;  // auto bind
    TransportId transport_id = PJSUA_INVALID_ID;
    if (args.transport == "udp") {
        transport_id = ep.transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
    } else if (args.transport == "tcp") {
        transport_id = ep.transportCreate(PJSIP_TRANSPORT_TCP, tcfg);
    } else if (args.transport == "tls") {
        transport_id = ep.transportCreate(PJSIP_TRANSPORT_TLS, tcfg);
    } else {
        std::cerr << "Unknown transport: " << args.transport << "\n";
        return 2;
    }

    ep.libStart();

    if (args.null_audio) {
        try {
            ep.audDevManager().setNullDev();
            std::cout << "Using null audio device\n";
        } catch (Error& err) {
            std::cerr << "Failed to set null audio device: " << err.info() << "\n";
        }
    }

    AccountConfig acc_cfg;
    if (!args.display_name.empty()) {
        acc_cfg.idUri = "\"" + args.display_name + "\" <" + args.local_id + ">";
    } else {
        acc_cfg.idUri = args.local_id;
    }
    if (transport_id != PJSUA_INVALID_ID) {
        acc_cfg.sipConfig.transportId = transport_id;
    }
    if (!args.outbound_proxy.empty()) {
        acc_cfg.sipConfig.proxies.push_back(args.outbound_proxy);
    }

    auto to_sips_contact = [&](const std::string& contact) -> std::string {
        if (contact.rfind("sips:", 0) == 0) {
            return contact;
        }
        if (contact.rfind("sip:", 0) == 0) {
            return "sips:" + contact.substr(4);
        }
        return "sips:" + contact;
    };

    if (!args.contact_forced.empty()) {
        acc_cfg.sipConfig.contactForced =
            (args.force_sips_contact || args.transport == "tls") ? to_sips_contact(args.contact_forced)
                                                                 : args.contact_forced;
    } else if (args.force_sips_contact) {
        std::string userpart = args.local_id;
        if (userpart.rfind("sip:", 0) == 0) userpart = userpart.substr(4);
        if (userpart.rfind("sips:", 0) == 0) userpart = userpart.substr(5);
        auto at = userpart.find('@');
        if (at != std::string::npos) userpart = userpart.substr(0, at);

        try {
            TransportInfo ti = ep.transportGetInfo(transport_id);
            std::string hostport = ti.localName;
            std::string contact = "sips:" + userpart + "@" + hostport + ";transport=tls";
            acc_cfg.sipConfig.contactForced = contact;
        } catch (Error&) {
            std::cerr << "Failed to build SIPS contact; provide --contact-forced.\n";
        }
    }

    if (!args.auth_user.empty()) {
        AuthCredInfo cred("digest", args.auth_realm, args.auth_user, 0, args.auth_pass);
        acc_cfg.sipConfig.authCreds.push_back(cred);
    }

    if (!args.registrar_ip.empty() && args.registrar_uri.empty()) {
        args.registrar_uri = "sips:" + args.registrar_ip + ":5061;transport=tls";
    }
    if (!args.registrar_uri.empty()) {
        acc_cfg.regConfig.registrarUri = args.registrar_uri;
    }
    acc_cfg.regConfig.registerOnAdd = args.register_on_add;
    acc_cfg.mediaConfig.lockCodecEnabled = false;
    acc_cfg.mediaConfig.streamKaEnabled = true;

    SmokeAccount account;
    account.create(acc_cfg);

    {
        if (args.prefer_opus) {
            try {
                auto codecs = ep.codecEnum2();
                for (const auto& c : codecs) {
                    ep.codecSetPriority(c.codecId, 0);
                }
                ep.codecSetPriority("opus/48000/2", 255);
                ep.codecSetPriority("telephone-event/8000", 128);
                ep.codecSetPriority("PCMU/8000", 64);
            } catch (Error&) {
                std::cerr << "Failed to set codec priorities; continuing with defaults.\n";
            }
        }

        if (args.register_on_add && args.wait_for_register) {
            auto start = std::chrono::steady_clock::now();
            bool reg_ok = false;
            while (std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::steady_clock::now() - start)
                       .count() < 30) {
                try {
                    AccountInfo ai = account.getInfo();
                    if (ai.regStatus >= 200 && ai.regStatus < 300) {
                        reg_ok = true;
                        std::cout << "Registration OK (" << ai.regStatusText << ")\n";
                        break;
                    }
                    if (ai.regStatus >= 300) {
                        std::cerr << "Registration failed (" << ai.regStatusText << ")\n";
                        break;
                    }
                } catch (Error&) {
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            if (!reg_ok) {
                if (!args.register_optional) {
                    std::cerr << "Proceeding without successful registration\n";
                }
            }
        }

        SmokeCall call(account);
        AudioMediaRecorder recorder;
        bool recorder_active = false;
        bool video_ok = false;
        if (args.enable_video) {
            try {
                auto vcodecs = ep.videoCodecEnum2();
                video_ok = !vcodecs.empty();
            } catch (Error&) {
                video_ok = false;
            }
            if (!video_ok) {
                std::cerr << "Video requested but not available in this PJSIP build; continuing audio-only.\n";
            }
        }

        CallOpParam prm(true);
        if (args.enable_video && video_ok) {
            CallSetting call_setting;
            call_setting.videoCount = 1;
            prm.opt = call_setting;
        }

        std::string dst_uri = args.sip_uri;
        if (args.transport == "tls" && dst_uri.find(";transport=") == std::string::npos) {
            dst_uri += ";transport=tls";
        } else if (args.transport == "tcp" && dst_uri.find(";transport=") == std::string::npos) {
            dst_uri += ";transport=tcp";
        } else if (args.transport == "udp" && dst_uri.find(";transport=") == std::string::npos) {
            dst_uri += ";transport=udp";
        }

        std::cout << "Dialing: " << dst_uri << "\n";
        call.makeCall(dst_uri, prm);

        const auto start = std::chrono::steady_clock::now();
        auto last_stats = start;
        auto last_keepalive = start;
        while (!g_shutdown.load() && !call.disconnected.load()) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > args.max_seconds) {
                std::cout << "Max duration reached, hanging up\n";
                try {
                    call.hangup(CallOpParam());
                } catch (Error&) {
                }
                break;
            }
            auto now = std::chrono::steady_clock::now();
            if (!recorder_active && !args.record_file.empty()) {
                try {
                    AudioMedia am = call.getAudioMedia(-1);
                    recorder.createRecorder(args.record_file);
                    am.startTransmit(recorder);
                    recorder_active = true;
                    std::cout << "Recording audio to " << args.record_file << "\n";
                } catch (Error&) {
                    // Will retry on next loop
                }
            }

            if (args.sip_keepalive_sec > 0) {
                auto since_ka = now - last_keepalive;
                if (std::chrono::duration_cast<std::chrono::seconds>(since_ka).count() >= args.sip_keepalive_sec) {
                    try {
                        CallSendRequestParam prm;
                        prm.method = "OPTIONS";
                        call.sendRequest(prm);
                    } catch (Error&) {
                    }
                    last_keepalive = now;
                }
            }

            auto since_stats = now - last_stats;
            if (args.stats_interval_sec > 0 &&
                std::chrono::duration_cast<std::chrono::seconds>(since_stats).count() >= args.stats_interval_sec) {
                print_audio_stats(call);
                last_stats = now;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }  // Call object destroyed before account/endpoint shutdown

    try {
        account.shutdown();
    } catch (Error&) {
    }

    try {
        ep.libDestroy();
    } catch (Error&) {
    }

    return 0;
}
