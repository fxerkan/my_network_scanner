// JavaScript Translation System for MyNeS
// Handles client-side translations

class TranslationManager {
    constructor() {
        this.translations = {};
        this.currentLanguage = 'tr';
        this.loaded = false;
    }

    async loadTranslations() {
        try {
            const response = await fetch('/api/language/info');
            const languageInfo = await response.json();
            
            this.currentLanguage = languageInfo.current;
            
            // Load translations for current language
            const translationResponse = await fetch(`/api/language/translations/${this.currentLanguage}`);
            this.translations = await translationResponse.json();
            
            this.loaded = true;
            return true;
        } catch (error) {
            console.error('Failed to load translations:', error);
            this.loaded = false;
            return false;
        }
    }

    t(key, params = {}) {
        if (!this.loaded || !this.translations[key]) {
            return key;
        }

        let translation = this.translations[key];
        
        // Replace parameters in translation
        Object.keys(params).forEach(param => {
            const placeholder = `{${param}}`;
            translation = translation.replace(new RegExp(placeholder, 'g'), params[param]);
        });

        return translation;
    }

    // Convenience method for pluralization
    tPlural(key, count, params = {}) {
        const translation = this.t(key, {...params, count: count});
        return translation;
    }

    isLoaded() {
        return this.loaded;
    }

    getCurrentLanguage() {
        return this.currentLanguage;
    }
}

// Global translation manager instance
const translationManager = new TranslationManager();

// Global translation function
function t(key, params = {}) {
    return translationManager.t(key, params);
}

// Language management function
async function changeLanguage(languageCode) {
    try {
        const response = await fetch('/api/language/set', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ language: languageCode })
        });
        
        const result = await response.json();
        if (result.success) {
            // Reload the page to apply the new language
            window.location.reload();
        } else {
            console.error('Failed to change language:', result.error);
        }
    } catch (error) {
        console.error('Error changing language:', error);
    }
}

// Initialize translations when DOM is loaded
document.addEventListener('DOMContentLoaded', async function() {
    await translationManager.loadTranslations();
    
    // Trigger a custom event when translations are loaded
    window.dispatchEvent(new CustomEvent('translationsLoaded'));
});