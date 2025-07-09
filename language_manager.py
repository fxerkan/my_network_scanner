#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Language Manager - Multi-language support for MyNeS
Provides translation support for Turkish and English
"""

import json
import os
from flask import session, request

class LanguageManager:
    def __init__(self):
        self.default_language = 'tr'
        self.supported_languages = ['tr', 'en']
        self.translations = {}
        self.load_translations()
    
    def load_translations(self):
        """Load all translation files"""
        for lang in self.supported_languages:
            translation_file = f"locales/{lang}/translations.json"
            try:
                if os.path.exists(translation_file):
                    with open(translation_file, 'r', encoding='utf-8') as f:
                        self.translations[lang] = json.load(f)
                        print(f"✅ {lang.upper()} translations loaded: {len(self.translations[lang])} entries")
                else:
                    print(f"⚠️ Translation file not found: {translation_file}")
                    self.translations[lang] = {}
            except Exception as e:
                print(f"❌ Error loading translations for {lang}: {e}")
                self.translations[lang] = {}
    
    def get_current_language(self):
        """Get current language from session or browser preference"""
        # Check session first
        if 'language' in session:
            lang = session['language']
            if lang in self.supported_languages:
                return lang
        
        # Check browser language preference
        if request and hasattr(request, 'accept_languages'):
            for lang in request.accept_languages:
                lang_code = lang[0][:2].lower()
                if lang_code in self.supported_languages:
                    return lang_code
        
        # Return default
        return self.default_language
    
    def set_language(self, language_code):
        """Set current language"""
        if language_code in self.supported_languages:
            session['language'] = language_code
            return True
        return False
    
    def get_translation(self, key, language=None, default=None):
        """Get translation for a specific key"""
        if language is None:
            language = self.get_current_language()
        
        if language in self.translations:
            translation = self.translations[language].get(key, default or key)
            return translation
        
        # Fallback to default language
        if self.default_language in self.translations:
            translation = self.translations[self.default_language].get(key, default or key)
            return translation
        
        # Last resort: return the key or default
        return default or key
    
    def get_all_translations(self, language=None):
        """Get all translations for a language"""
        if language is None:
            language = self.get_current_language()
        
        return self.translations.get(language, {})
    
    def get_language_info(self):
        """Get information about available languages"""
        return {
            'current': self.get_current_language(),
            'supported': self.supported_languages,
            'default': self.default_language,
            'names': {
                'tr': 'Türkçe',
                'en': 'English'
            },
            'flags': {
                'tr': '🇹🇷',
                'en': '🇺🇸'
            }
        }

# Global instance
language_manager = LanguageManager()

def _(key, **kwargs):
    """Translation function - shorthand for get_translation"""
    translation = language_manager.get_translation(key)
    
    # Format with kwargs if provided
    if kwargs:
        try:
            translation = translation.format(**kwargs)
        except (KeyError, ValueError):
            pass
    
    return translation

def get_language_manager():
    """Get the global language manager instance"""
    return language_manager