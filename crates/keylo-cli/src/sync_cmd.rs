//! keylo sync: keeping secrets in step across your own devices through a shared folder (see
//! keylo_core::sync).

use std::path::PathBuf;

use keylo_core::sync::{self, Device};

use crate::args::{Args, CliResult};
use crate::terminal::{self, info, print_table};
use crate::{usage, Context};

pub fn sync_cmd(c: &mut Context, args: &Args) -> CliResult<i32> {
    let action = args.optional_positional(0).map(|a| a.to_lowercase()).unwrap_or_else(|| "now".into());
    let dev = Device::local();
    match action.as_str() {
        "now" => {
            args.throw_on_unknown(Some(1))?;
            // A sync reads every value, so it needs the identity check (or a session).
            c.browse()?;
            report(&sync::sync(&dev)?)
        }
        "status" => {
            args.throw_on_unknown(Some(1))?;
            print_status(&dev)
        }
        "create" => {
            let folder = PathBuf::from(args.positional(1, "folder")?);
            let name = args.option("name").unwrap_or_else(sync::default_device_name);
            args.throw_on_unknown(Some(2))?;
            c.browse()?;
            let r = sync::create(&dev, &folder, &name)?;
            info(&format!("Syncing {} as '{name}'.", folder.display()));
            info("To add another device, run 'keylo sync code' here, then 'keylo sync join FOLDER' there.");
            report(&r)
        }
        "join" => {
            let folder = PathBuf::from(args.positional(1, "folder")?);
            let name = args.option("name").unwrap_or_else(sync::default_device_name);
            args.throw_on_unknown(Some(2))?;
            c.browse()?;
            let code = terminal::read_secret("Join code (from 'keylo sync code' or Settings → Sync on a device that syncs): ", false)?;
            let code = String::from_utf8_lossy(&code).into_owned();
            let r = sync::join(&dev, &folder, &name, &code)?;
            info(&format!("Joined {} as '{name}'.", folder.display()));
            report(&r)
        }
        "code" => {
            args.throw_on_unknown(Some(1))?;
            // The code is the vault key: always ask, even during a session.
            c.gate.confirm(0, "Keylo: show the sync join code")?;
            let code = sync::join_code(&dev)?;
            info("Enter this on the device that's joining. Anyone with it and the folder can read every synced secret.");
            println!("{code}");
            Ok(0)
        }
        "rename" => {
            let name = args.positional(1, "device name")?;
            args.throw_on_unknown(Some(2))?;
            sync::rename_device(&dev, &name)?;
            info(&format!("This device is now '{name}'; the others see it after the next sync."));
            Ok(0)
        }
        "forget" => {
            let which = args.positional(1, "device id or name")?;
            args.throw_on_unknown(Some(2))?;
            let status = sync::status(&dev)?.ok_or_else(|| keylo_core::Error::msg("This device doesn't sync."))?;
            let matches: Vec<_> = status.devices.iter().filter(|d| !d.this_device && (d.id == which || keylo_core::eq_ic(&d.name, &which))).collect();
            let device = match matches.as_slice() {
                [d] => *d,
                [] => usage!("No other device '{which}'. 'keylo sync status' lists them."),
                _ => usage!("More than one device is called '{which}'; use its id from 'keylo sync status'."),
            };
            sync::forget(&dev, &device.id)?;
            info(&format!(
                "Removed '{}' from the sync folder. It still knows the vault's code and secrets; if it still syncs, its file comes back.",
                device.name
            ));
            Ok(0)
        }
        "leave" => {
            let yes = args.flag("yes");
            args.throw_on_unknown(Some(1))?;
            if sync::status(&dev)?.is_none() {
                info("This device doesn't sync.");
                return Ok(0);
            }
            if !yes && !terminal::confirm("Stop syncing on this device? Its secrets stay here and on the other devices.") {
                info("Still syncing.");
                return Ok(1);
            }
            sync::leave(&dev)?;
            info("Stopped syncing on this device.");
            Ok(0)
        }
        _ => usage!("keylo sync [now | status | create FOLDER | join FOLDER | code | rename NAME | forget DEVICE | leave]"),
    }
}

fn report(r: &sync::Report) -> CliResult<i32> {
    info(&r.summary());
    for name in &r.conflicts {
        info(&format!("  Kept a conflicting version as '{name}'."));
    }
    for e in &r.errors {
        info(&format!("  Not applied: {e}"));
    }
    Ok(if r.errors.is_empty() { 0 } else { 1 })
}

fn print_status(dev: &Device) -> CliResult<i32> {
    let Some(s) = sync::status(dev)? else {
        info("This device doesn't sync. Start with 'keylo sync create FOLDER', or 'keylo sync join FOLDER' to join another device.");
        return Ok(0);
    };
    println!("folder     {}", s.folder.display());
    println!("this       {} ({})", s.device_name, s.device_id);
    match &s.last {
        Some(l) => println!("last sync  {} · {}", l.at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M"), l.summary),
        None => println!("last sync  never"),
    }
    if let Some(p) = &s.problem {
        println!("problem    {p}");
    }
    let rows: Vec<Vec<String>> = s
        .devices
        .iter()
        .map(|d| {
            vec![
                if d.this_device { format!("{} (this)", d.name) } else { d.name.clone() },
                d.platform.clone(),
                d.synced_at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string(),
                d.id.clone(),
            ]
        })
        .collect();
    println!();
    print_table(&["DEVICE", "OS", "LAST SYNC", "ID"], &rows);
    Ok(0)
}
