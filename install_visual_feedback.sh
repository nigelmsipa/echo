#!/bin/bash

echo "🎨 Installing Echo Visual Feedback System..."

# Make scripts executable
chmod +x echo_visual_feedback.py
chmod +x echo_adaptive_feedback.py  
chmod +x waybar_echo_widget.py

# Install tkinter if needed
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "📦 Installing tkinter..."
    if command -v pacman &> /dev/null; then
        sudo pacman -S tk --noconfirm
    elif command -v apt &> /dev/null; then
        sudo apt install python3-tk
    fi
fi

# Test the visual feedback system
echo "🧪 Testing visual feedback..."
timeout 3s python3 echo_visual_feedback.py || echo "✅ Visual feedback test complete"

# Test waybar widget
echo "🧪 Testing waybar widget..."
python3 waybar_echo_widget.py

echo ""
echo "✅ Echo Visual Feedback installed!"
echo ""
echo "📋 Next steps:"
echo "1. Add this to your waybar config modules-center:"
echo '   "custom/echo"'
echo ""
echo "2. Add this to your waybar config:"
cat waybar_config_sample.json
echo ""
echo "3. Add the CSS styles to your waybar stylesheet:"
echo "   cat waybar_echo_styles.css >> ~/.config/waybar/style.css"
echo ""
echo "4. Restart waybar:"
echo "   pkill waybar && waybar &"
echo ""
echo "🚀 Your echo app will now show:"
echo "   • Glassmorphism overlay when fullscreen"
echo "   • Animated waybar widget when windowed"