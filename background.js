// background.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyze_element') {
        fetch('http://localhost:5000/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                content: {
                    elements: {
                        [request.tag]: [request.html]
                    }
                }
            })
        })
        .then(response => response.json())
        .then(data => {
            const isMalicious = data.malicious_elements?.[request.tag]?.some(e => e);
            sendResponse({ malicious: isMalicious });
        })
        .catch(error => {
            console.error('Analysis failed:', error);
            sendResponse({ malicious: false });
        });
        return true;  // Keep channel open
    }
});