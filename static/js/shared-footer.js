// Shared Footer functionality for MyNeS
// Loads version information and creates consistent footer across all pages

class FooterManager {
    constructor() {
        this.versionInfo = null;
    }

    async loadVersion() {
        try {
            const response = await fetch('/api/version');
            this.versionInfo = await response.json();
            this.updateFooter();
        } catch (error) {
            console.error('Version loading error:', error);
            // Use default version in case of error
            this.versionInfo = { version: '1.0.0' };
            this.updateFooter();
        }
    }

    updateFooter() {
        const versionElement = document.getElementById('appVersion');
        if (versionElement && this.versionInfo && this.versionInfo.version) {
            versionElement.textContent = `v${this.versionInfo.version}`;
            
            // Add detailed info as tooltip
            if (this.versionInfo.commit) {
                const tooltip = [
                    `Version: ${this.versionInfo.version}`,
                    this.versionInfo.commit ? `Commit: ${this.versionInfo.commit.slice(0, 7)}` : '',
                    this.versionInfo.build_time ? `Built: ${new Date(this.versionInfo.build_time).toLocaleString()}` : '',
                    this.versionInfo.is_dirty ? 'Modified' : ''
                ].filter(Boolean).join('\n');
                
                versionElement.title = tooltip;
            }
        }
    }

    createFooter() {
        return `
            <footer style="
                background: linear-gradient(45deg, #2c3e50, #34495e);
                color: white;
                text-align: center;
                padding: 15px;
                margin-top: 20px;
                border-radius: 15px;
                min-height: 60px;
                display: flex;
                align-items: center;
                justify-content: center;
            ">
                <div style="display: flex; justify-content: center; align-items: center; gap: 20px; flex-wrap: wrap;">
                    <div>
                        <strong>My Network Scanner (MyNeS)</strong> <span id="appVersion">v1.0.0</span>
                    </div>
                    <div>|</div>
                    <div>
                        Your Family's User-Friendly Network Scanner
                    </div>
                    <div>|</div>
                    <div>
                        <a href="https://github.com/fxerkan/my-network-scanner" target="_blank" style="
                            color: #74b9ff;
                            text-decoration: none;
                            display: inline-flex;
                            align-items: center;
                            gap: 5px;
                            transition: color 0.3s ease;
                        " onmouseover="this.style.color='#0984e3'" onmouseout="this.style.color='#74b9ff'">
                            🐙 github.com/fxerkan/my-network-scanner
                        </a>
                    </div>
                </div>
            </footer>
        `;
    }

    async initializeFooter() {
        // Create footer if it doesn't exist
        let footer = document.querySelector('footer');
        if (!footer) {
            const container = document.querySelector('.container') || document.body;
            container.insertAdjacentHTML('beforeend', this.createFooter());
        }
        
        // Load version information
        await this.loadVersion();
    }
}

// Global footer manager instance
const footerManager = new FooterManager();

// Initialize footer when DOM is loaded
document.addEventListener('DOMContentLoaded', async function() {
    await footerManager.initializeFooter();
});