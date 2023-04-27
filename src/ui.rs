use std::{
    collections::HashMap,
    iter::FromIterator,
    process::Child,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;
#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
    static ref CHILDREN : Children = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    #[cfg(all(windows, not(feature = "inline")))]
    unsafe {
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        let children: Children = Default::default();
        std::thread::spawn(move || check_zombie(children));
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let cmd = iter.next().unwrap().clone();
        let id = iter.next().unwrap().clone();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> = serde_json::from_str(&get_options()).unwrap();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.0);
        v.push(x.1);
        v.push(x.3);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers()
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(id)
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

pub fn check_zombie(children: Children) {
    let mut deads = Vec::new();
    loop {
        let mut lock = children.lock().unwrap();
        let mut n = 0;
        for (id, c) in lock.1.iter_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                deads.push(id.clone());
                n += 1;
            }
        }
        for ref id in deads.drain(..) {
            lock.1.remove(id);
        }
        if n > 0 {
            lock.0 = true;
        }
        drop(lock);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

#[inline]
pub fn new_remote(id: String, remote_type: String, force_relay: bool) {
    let mut lock = CHILDREN.lock().unwrap();
    let mut args = vec![format!("--{}", remote_type), id.clone()];
    if force_relay {
        args.push("".to_string()); // password
        args.push("--relay".to_string());
    }
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                return;
            }
        }
    }
    match crate::run_me(args) {
        Ok(child) => {
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
}

#[inline]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
