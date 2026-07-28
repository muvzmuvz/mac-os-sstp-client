// One-off helper: generates assets/AppIcon.iconset/*.png from a procedurally
// drawn 1024x1024 master icon (blue squircle + white padlock), then invokes
// the macOS `iconutil` tool to produce assets/AppIcon.icns.
use image::{Rgba, RgbaImage};

const SIZE: u32 = 1024;

fn superellipse_inside(nx: f32, ny: f32, n: f32) -> bool {
    nx.abs().powf(n) + ny.abs().powf(n) <= 1.0
}

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

fn draw_master() -> RgbaImage {
    let mut img = RgbaImage::new(SIZE, SIZE);
    let center = SIZE as f32 / 2.0;
    let half = SIZE as f32 / 2.0;

    // Padlock geometry, normalized to icon size.
    let body_w = SIZE as f32 * 0.40;
    let body_h = SIZE as f32 * 0.34;
    let body_top = SIZE as f32 * 0.50;
    let body_cx = center;
    let body_cy = body_top + body_h / 2.0;
    let body_corner = SIZE as f32 * 0.07;

    let shackle_outer_r = SIZE as f32 * 0.19;
    let shackle_inner_r = SIZE as f32 * 0.105;
    let shackle_cy = body_top;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let nx = (fx - center) / half;
            let ny = (fy - center) / half;

            if !superellipse_inside(nx, ny, 5.0) {
                img.put_pixel(x, y, Rgba([0, 0, 0, 0]));
                continue;
            }

            // Background vertical gradient, deep blue to teal.
            let t = fy / SIZE as f32;
            let r = lerp(0x1B as f32, 0x11 as f32, t);
            let g = lerp(0x5B as f32, 0x9B as f32, t);
            let b = lerp(0xC9 as f32, 0xA8 as f32, t);
            let mut pixel = [r as u8, g as u8, b as u8, 255u8];

            // Shackle: upper half of a ring, sitting on top of the body.
            let dx = fx - body_cx;
            let dy = fy - shackle_cy;
            let dist = (dx * dx + dy * dy).sqrt();
            if dy <= shackle_outer_r * 0.55
                && dist >= shackle_inner_r
                && dist <= shackle_outer_r
            {
                pixel = [255, 255, 255, 255];
            }

            // Body: rounded rectangle via superellipse in local coords.
            let lx = (fx - body_cx) / (body_w / 2.0);
            let ly = (fy - body_cy) / (body_h / 2.0);
            let corner_n = SIZE as f32 / body_corner;
            if superellipse_inside(lx, ly, corner_n.clamp(2.5, 6.0)) {
                pixel = [255, 255, 255, 255];
            }

            // Keyhole cutout inside the body.
            let khx = fx - body_cx;
            let khy = fy - body_cy;
            let hole_r = SIZE as f32 * 0.035;
            let slot_w = SIZE as f32 * 0.028;
            let slot_h = SIZE as f32 * 0.075;
            let in_circle = (khx * khx + (khy + hole_r * 0.3) * (khy + hole_r * 0.3)).sqrt() <= hole_r;
            let in_slot = khx.abs() <= slot_w / 2.0 && khy >= -hole_r * 0.3 && khy <= slot_h;
            if in_circle || in_slot {
                let bg_r = lerp(0x1B as f32, 0x11 as f32, fy / SIZE as f32) as u8;
                let bg_g = lerp(0x5B as f32, 0x9B as f32, fy / SIZE as f32) as u8;
                let bg_b = lerp(0xC9 as f32, 0xA8 as f32, fy / SIZE as f32) as u8;
                pixel = [bg_r, bg_g, bg_b, 255];
            }

            img.put_pixel(x, y, Rgba(pixel));
        }
    }

    img
}

fn main() {
    let master = draw_master();
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    let iconset = assets.join("AppIcon.iconset");
    std::fs::create_dir_all(&iconset).unwrap();

    let sizes: &[(u32, &str)] = &[
        (16, "icon_16x16.png"),
        (32, "icon_16x16@2x.png"),
        (32, "icon_32x32.png"),
        (64, "icon_32x32@2x.png"),
        (128, "icon_128x128.png"),
        (256, "icon_128x128@2x.png"),
        (256, "icon_256x256.png"),
        (512, "icon_256x256@2x.png"),
        (512, "icon_512x512.png"),
        (1024, "icon_512x512@2x.png"),
    ];

    for (size, name) in sizes {
        let resized = image::imageops::resize(&master, *size, *size, image::imageops::FilterType::Lanczos3);
        resized.save(iconset.join(name)).unwrap();
    }

    let icns_path = assets.join("AppIcon.icns");
    let status = std::process::Command::new("iconutil")
        .args(["-c", "icns", iconset.to_str().unwrap(), "-o", icns_path.to_str().unwrap()])
        .status()
        .expect("failed to run iconutil");
    assert!(status.success(), "iconutil failed");
    println!("Wrote {}", icns_path.display());
}
