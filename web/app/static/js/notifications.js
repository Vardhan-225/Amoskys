/**
 * AMOSKYS Dashboard Notification System - Phase 9
 * Enhanced user feedback with animations and sound support
 */

class NotificationSystem {
    constructor(options = {}) {
        this.container = options.container || document.body;
        this.position = options.position || 'bottom-right';
        this.duration = options.duration || 4000;
        this.maxNotifications = options.maxNotifications || 5;
        this.soundEnabled = options.soundEnabled || false;
        this.notifications = [];
        
        this.init();
    }
    
    init() {
        // Create container
        this.notificationContainer = document.createElement('div');
        this.notificationContainer.id = 'notification-container';
        this.notificationContainer.style.cssText = `
            position: fixed;
            ${this.position === 'bottom-right' ? 'bottom: 20px; right: 20px;' : 'top: 20px; right: 20px;'}
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
            max-width: 400px;
            pointer-events: none;
        `;
        document.body.appendChild(this.notificationContainer);
    }
    
    /**
     * Show a success notification
     */
    success(message, title = '✅ Success', duration = null) {
        return this.show(message, 'success', title, duration);
    }
    
    /**
     * Show an error notification
     */
    error(message, title = '❌ Error', duration = null) {
        return this.show(message, 'error', title, duration || 6000);
    }
    
    /**
     * Show an info notification
     */
    info(message, title = 'ℹ️ Info', duration = null) {
        return this.show(message, 'info', title, duration);
    }
    
    /**
     * Show a warning notification
     */
    warning(message, title = '⚠️ Warning', duration = null) {
        return this.show(message, 'warning', title, duration || 5000);
    }
    
    /**
     * Show a loading notification
     */
    loading(message, title = '⏳ Loading') {
        return this.show(message, 'loading', title, null);
    }
    
    /**
     * Main show method
     */
    show(message, type = 'info', title = '', duration = null) {
        // Check if we've hit max notifications
        if (this.notifications.length >= this.maxNotifications) {
            const oldest = this.notifications.shift();
            oldest.element.remove();
        }
        
        duration = duration !== null ? duration : this.duration;
        
        // Create notification element
        const notificationId = `notification-${Date.now()}`;
        const notification = document.createElement('div');
        notification.id = notificationId;
        notification.className = `notification notification-${type}`;
        
        const colors = {
            success: '#00ff88',
            error: '#ff3366',
            warning: '#ffaa00',
            info: '#0088ff',
            loading: '#00ffff'
        };
        
        const bgColors = {
            success: 'rgba(0, 255, 136, 0.15)',
            error: 'rgba(255, 51, 102, 0.15)',
            warning: 'rgba(255, 170, 0, 0.15)',
            info: 'rgba(0, 136, 255, 0.15)',
            loading: 'rgba(0, 255, 255, 0.15)'
        };
        
        notification.style.cssText = `
            background: ${bgColors[type]};
            border: 1px solid ${colors[type]};
            color: ${colors[type]};
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            animation: toast-slide-in 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            pointer-events: auto;
            cursor: pointer;
            position: relative;
            overflow: hidden;
        `;
        
        // Create content
        const content = document.createElement('div');
        content.style.cssText = `
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 4px;
        `;
        
        if (title) {
            const titleEl = document.createElement('div');
            titleEl.style.cssText = `
                font-weight: 600;
                font-size: 0.95rem;
            `;
            titleEl.textContent = title;
            content.appendChild(titleEl);
        }
        
        if (message) {
            const messageEl = document.createElement('div');
            messageEl.style.cssText = `
                font-size: 0.85rem;
                opacity: 0.9;
            `;
            messageEl.textContent = message;
            content.appendChild(messageEl);
        }
        
        notification.appendChild(content);
        
        // Add loading spinner for loading notifications
        if (type === 'loading') {
            const spinner = document.createElement('div');
            spinner.style.cssText = `
                width: 16px;
                height: 16px;
                border: 2px solid ${colors[type]};
                border-radius: 50%;
                border-top: 2px solid rgba(0, 255, 255, 0.3);
                animation: spin 1s linear infinite;
                flex-shrink: 0;
            `;
            notification.insertBefore(spinner, content);
        }
        
        // Add close button
        const closeBtn = document.createElement('button');
        closeBtn.style.cssText = `
            background: transparent;
            border: none;
            color: ${colors[type]};
            cursor: pointer;
            font-size: 1.2rem;
            padding: 0;
            display: flex;
            align-items: center;
            opacity: 0.7;
            transition: opacity 0.2s;
        `;
        closeBtn.innerHTML = '×';
        closeBtn.onclick = (e) => {
            e.stopPropagation();
            this.remove(notificationId);
        };
        closeBtn.onmouseover = () => { closeBtn.style.opacity = '1'; };
        closeBtn.onmouseout = () => { closeBtn.style.opacity = '0.7'; };
        notification.appendChild(closeBtn);
        
        // Add progress bar for timed notifications
        if (duration > 0) {
            const progressBar = document.createElement('div');
            progressBar.style.cssText = `
                position: absolute;
                bottom: 0;
                left: 0;
                height: 2px;
                background: ${colors[type]};
                animation: progress-shrink ${duration}ms linear forwards;
            `;
            notification.appendChild(progressBar);
            
            // Add animation
            const style = document.createElement('style');
            style.textContent = `
                @keyframes progress-shrink {
                    from { width: 100%; }
                    to { width: 0%; }
                }
            `;
            document.head.appendChild(style);
        }
        
        this.notificationContainer.appendChild(notification);
        
        // Play sound if enabled
        if (this.soundEnabled) {
            this.playSound(type);
        }
        
        // Store reference
        const notifObj = {
            id: notificationId,
            element: notification,
            type: type
        };
        this.notifications.push(notifObj);
        
        // Auto-remove after duration
        if (duration > 0) {
            setTimeout(() => {
                this.remove(notificationId);
            }, duration);
        }
        
        return notifObj;
    }
    
    /**
     * Remove a notification
     */
    remove(notificationId) {
        const index = this.notifications.findIndex(n => n.id === notificationId);
        if (index >= 0) {
            const notification = this.notifications[index];
            notification.element.style.animation = 'toast-slide-out 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
            
            setTimeout(() => {
                if (notification.element.parentNode) {
                    notification.element.remove();
                }
                this.notifications.splice(index, 1);
            }, 300);
        }
    }
    
    /**
     * Clear all notifications
     */
    clear() {
        this.notifications.forEach(notif => notif.element.remove());
        this.notifications = [];
    }
    
    /**
     * Play notification sound
     */
    playSound(type) {
        // Simple beep implementation
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            // Different frequencies for different types
            const frequencies = {
                success: 800,
                error: 400,
                warning: 600,
                info: 700,
                loading: 500
            };
            
            oscillator.frequency.value = frequencies[type] || 500;
            oscillator.type = 'sine';
            
            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.1);
        } catch (e) {
            // Audio context not available, silently fail
        }
    }
    
    /**
     * Show a confirmation dialog
     */
    confirm(message, title = 'Confirm', onConfirm = null, onCancel = null) {
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10001;
            animation: fade-in 0.2s ease;
        `;
        
        const dialog = document.createElement('div');
        dialog.style.cssText = `
            background: #1a1a1a;
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 24px;
            max-width: 400px;
            box-shadow: 0 8px 32px rgba(0, 255, 136, 0.2);
            animation: slide-in-up 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        `;
        
        const titleEl = document.createElement('h3');
        titleEl.style.cssText = `
            color: #00ff88;
            margin: 0 0 12px 0;
            font-size: 1.1rem;
        `;
        titleEl.textContent = title;
        dialog.appendChild(titleEl);
        
        const messageEl = document.createElement('p');
        messageEl.style.cssText = `
            color: #cccccc;
            margin: 0 0 20px 0;
            line-height: 1.5;
        `;
        messageEl.textContent = message;
        dialog.appendChild(messageEl);
        
        const buttonContainer = document.createElement('div');
        buttonContainer.style.cssText = `
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        `;
        
        const cancelBtn = document.createElement('button');
        cancelBtn.style.cssText = `
            background: #2a2a2a;
            color: #cccccc;
            border: 1px solid #444444;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
        `;
        cancelBtn.textContent = 'Cancel';
        cancelBtn.onclick = () => {
            overlay.remove();
            if (onCancel) onCancel();
        };
        
        const confirmBtn = document.createElement('button');
        confirmBtn.style.cssText = `
            background: #00ff88;
            color: #000000;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 600;
        `;
        confirmBtn.textContent = 'Confirm';
        confirmBtn.onclick = () => {
            overlay.remove();
            if (onConfirm) onConfirm();
        };
        
        buttonContainer.appendChild(cancelBtn);
        buttonContainer.appendChild(confirmBtn);
        dialog.appendChild(buttonContainer);
        
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                overlay.remove();
                if (onCancel) onCancel();
            }
        });
        
        // Add fade-in animation if not already present
        if (!document.querySelector('style[data-animation="fade-in"]')) {
            const style = document.createElement('style');
            style.setAttribute('data-animation', 'fade-in');
            style.textContent = `
                @keyframes fade-in {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
            `;
            document.head.appendChild(style);
        }
    }
}

// Create global notification instance
window.notifications = new NotificationSystem({
    duration: 4000,
    maxNotifications: 5,
    soundEnabled: false
});

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NotificationSystem;
}
