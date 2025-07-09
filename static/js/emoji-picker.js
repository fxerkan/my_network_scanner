/**
 * Emoji Picker Module - CSV Based
 * Handles emoji selection popup for device type icons
 * Data is loaded from emojis.csv via API
 */

// Emoji Picker Global Variables
let currentEmojiTarget = null;
let currentEmojiFilter = 'all';
let emojisData = []; // Will be loaded from CSV
let emojiCategories = {}; // Will be built from CSV data

/**
 * Load emojis from CSV via API
 */
async function loadEmojisData() {
    try {
        const response = await fetch('/api/emojis');
        const data = await response.json();
        
        emojisData = data.emojis || [];
        
        // Build categories object from loaded data
        emojiCategories = {};
        emojisData.forEach(emoji => {
            const category = emoji.category;
            if (!emojiCategories[category]) {
                emojiCategories[category] = [];
            }
            emojiCategories[category].push(emoji.emoji);
        });
        
        return true;
    } catch (error) {
        console.error('Error loading emojis:', error);
        // Fallback to basic emoji set
        emojisData = [
            {emoji: '💻', category: 'tech', description: 'laptop computer', keywords: 'laptop computer tech'},
            {emoji: '📱', category: 'mobile', description: 'mobile phone', keywords: 'phone mobile smartphone'},
            {emoji: '🌐', category: 'network', description: 'network web', keywords: 'network web internet'},
            {emoji: '🔒', category: 'security', description: 'security lock', keywords: 'security lock closed'},
            {emoji: '🏠', category: 'smart', description: 'smart home', keywords: 'home smart house'},
            {emoji: '🎮', category: 'gaming', description: 'gaming controller', keywords: 'gaming game controller'},
            {emoji: '📺', category: 'entertainment', description: 'television', keywords: 'tv television entertainment'},
            {emoji: '🚗', category: 'transport', description: 'car vehicle', keywords: 'car vehicle transport'},
            {emoji: '🔧', category: 'tech', description: 'wrench tool', keywords: 'tool wrench repair'},
            {emoji: '⚙️', category: 'tech', description: 'gear settings', keywords: 'gear settings config'}
        ];
        emojiCategories = {
            'tech': ['💻', '🔧', '⚙️'],
            'mobile': ['📱'],
            'network': ['🌐'],
            'security': ['🔒'],
            'smart': ['🏠'],
            'gaming': ['🎮'],
            'entertainment': ['📺'],
            'transport': ['🚗']
        };
        return false;
    }
}

/**
 * Get all emojis for a specific category or all
 */
function getEmojisForCategory(category = 'all') {
    if (category === 'all') {
        return emojisData;
    }
    
    return emojisData.filter(emoji => emoji.category === category);
}

/**
 * Search emojis by keywords
 */
function searchEmojis(searchTerm) {
    if (!searchTerm) return emojisData;
    
    const term = searchTerm.toLowerCase();
    return emojisData.filter(emoji => {
        return emoji.keywords.toLowerCase().includes(term) || 
               emoji.description.toLowerCase().includes(term);
    });
}

/**
 * Emoji Picker Functions
 */
function openEmojiPicker(targetId) {
    currentEmojiTarget = targetId;
    const modal = document.getElementById('emojiPickerModal');
    modal.style.display = 'block';
    
    // Load emojis if not already loaded
    if (emojisData.length === 0) {
        loadEmojisData().then(() => {
            generateEmojiGrid();
            setupSearchHandler();
        });
    } else {
        generateEmojiGrid();
        setupSearchHandler();
    }
}

/**
 * Setup search input handler
 */
function setupSearchHandler() {
    // Wait for DOM to be ready
    setTimeout(() => {
        const searchInput = document.getElementById('emojiSearchInput');
        if (searchInput) {
            // Clear any existing search
            searchInput.value = '';
        }
    }, 100);
}

function closeEmojiPicker() {
    document.getElementById('emojiPickerModal').style.display = 'none';
    currentEmojiTarget = null;
}

function selectEmoji(emoji) {
    if (currentEmojiTarget) {
        document.getElementById(currentEmojiTarget).value = emoji;
    }
    closeEmojiPicker();
}

/**
 * Generate emoji grid from current data
 */
function generateEmojiGrid(filter = 'all') {
    const grid = document.getElementById('emojiGrid');
    if (!grid) return;
    
    let emojisToShow = getEmojisForCategory(filter);
    
    grid.innerHTML = emojisToShow.map(emojiData => 
        `<div class="emoji-item" onclick="selectEmoji('${emojiData.emoji}')" title="${emojiData.description}">${emojiData.emoji}</div>`
    ).join('');
}

/**
 * Filter emojis by category
 */
function filterEmojiCategory(category) {
    currentEmojiFilter = category;
    
    // Update button states
    document.querySelectorAll('[id^="category"]').forEach(btn => {
        btn.className = 'btn btn-small btn-secondary';
    });
    
    // Set active button
    const activeBtn = document.getElementById('category' + category.charAt(0).toUpperCase() + category.slice(1));
    if (activeBtn) {
        activeBtn.className = 'btn btn-small';
    }
    
    generateEmojiGrid(category);
}

/**
 * Search emojis by user input
 */
function searchEmojisHandler(event) {
    const searchInput = document.getElementById('emojiSearchInput');
    if (!searchInput) return;
    
    const grid = document.getElementById('emojiGrid');
    if (!grid) return;
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    
    if (!searchTerm) {
        // Show all emojis in current category
        generateEmojiGrid(currentEmojiFilter);
        return;
    }
    
    // Direct search without calling searchEmojis function to avoid recursion
    const filteredEmojis = emojisData.filter(emoji => {
        return emoji.keywords.toLowerCase().includes(searchTerm) || 
               emoji.description.toLowerCase().includes(searchTerm);
    });
    
    if (filteredEmojis.length === 0) {
        grid.innerHTML = '<div style="text-align: center; padding: 20px; color: #6c757d;">Arama sonucu bulunamadı</div>';
    } else {
        grid.innerHTML = filteredEmojis.map(emojiData => 
            `<div class="emoji-item" onclick="selectEmoji('${emojiData.emoji}')" title="${emojiData.description}">${emojiData.emoji}</div>`
        ).join('');
    }
}

/**
 * Get available categories
 */
function getAvailableCategories() {
    return Object.keys(emojiCategories);
}

/**
 * Add a new emoji (for admin use)
 */
async function addNewEmoji(emoji, category, description, keywords) {
    try {
        const response = await fetch('/api/emojis', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                emoji: emoji,
                category: category,
                description: description,
                keywords: keywords
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            // Reload emojis data
            await loadEmojisData();
            generateEmojiGrid(currentEmojiFilter);
            return { success: true, message: result.message };
        } else {
            return { success: false, error: result.error };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Initialize emoji system
 */
function initializeEmojiPicker() {
    // Load emojis on page load
    loadEmojisData();
}

/**
 * Test function for debugging
 */
function testEmojiSearch(term) {
    const results = searchEmojis(term);
    return results;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeEmojiPicker();
});

// Make functions globally accessible
window.openEmojiPicker = openEmojiPicker;
window.closeEmojiPicker = closeEmojiPicker;
window.selectEmoji = selectEmoji;
window.filterEmojiCategory = filterEmojiCategory;
window.searchEmojisHandler = searchEmojisHandler;
window.testEmojiSearch = testEmojiSearch;