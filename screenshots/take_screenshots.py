import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=[
            '--disable-gpu',
            '--no-sandbox',
            '--font-render-hinting=none',
        ])
        context = await browser.new_context(
            viewport={'width': 1440, 'height': 900},
            color_scheme='dark',
        )
        page = await context.new_page()

        # Dashboard screenshot
        print("Loading dashboard...")
        await page.goto('http://192.168.1.50:8766/#/dashboard', wait_until='networkidle')
        await page.wait_for_timeout(5000)
        await page.screenshot(path='/Users/timolow/opnsense-anomaly-agent/screenshots/dashboard.png', full_page=True)
        print("Dashboard screenshot saved")

        # Heatmap screenshot - wait for the actual heatmap canvas to render
        print("Loading heatmap...")
        await page.goto('http://192.168.1.50:8766/#/heatmap', wait_until='networkidle')
        # Wait for the heatmap canvas to exist and have actual data
        try:
            await page.wait_for_selector('canvas', timeout=15000)
        except Exception:
            print("WARNING: Heatmap canvas not found, waiting 15s anyway...")
            await page.wait_for_timeout(15000)
        await page.wait_for_timeout(5000)  # Extra time for grid to fully render
        await page.screenshot(path='/Users/timolow/opnsense-anomaly-agent/screenshots/heatmap.png', full_page=True)
        print("Heatmap screenshot saved")

        await browser.close()

asyncio.run(main())
