// content.js - Guaranteed Alert Prevention
const TAGS_TO_ALYZE = ['script', 'iframe', 'meta', 'svg', 'embed', 'link', 'form', 'style', 'input', 'textarea', 'div'];

// 1. Freeze execution
const freezeExecution = () => {
  window.eval = window.Function = () => {};
  document.write = document.close = () => {};
  Object.defineProperty(document, 'readyState', {
    get: () => 'loading',
    configurable: true
  });
};

// 2. Analyze elements and reinsert safe ones
const analyzePage = async () => {
  const elements = Array.from(document.querySelectorAll(TAGS_TO_ANALYZE.join(',')));
  
  await Promise.all(elements.map(el => {
    const parent = el.parentNode;
    const nextSibling = el.nextSibling;
    el.remove(); // Detach from DOM

    return new Promise(resolve => {
      chrome.runtime.sendMessage(
        { action: 'analyze_element', tag: el.tagName.toLowerCase(), html: el.outerHTML },
        (response) => {
          if (!response?.malicious) {
            // Reinsert safe elements (handle scripts specially)
            if (el.tagName.toLowerCase() === 'script') {
              const newScript = document.createElement('script');
              newScript.textContent = el.textContent;
              Array.from(el.attributes).forEach(attr => {
                newScript.setAttribute(attr.name, attr.value);
              });
              parent.insertBefore(newScript, nextSibling);
            } else {
              parent.insertBefore(el, nextSibling);
            }
          }
          resolve();
        }
      );
    });
  }));

  // 3. Resume parsing
  Object.defineProperty(document, 'readyState', { get: () => 'complete', configurable: false });
  document.dispatchEvent(new Event('DOMContentLoaded'));
};

// 4. Monitor dynamic content
new MutationObserver(mutations => {
  mutations.forEach(({ addedNodes }) => {
    addedNodes.forEach(node => {
      if (node.nodeType === 1 && TAGS_TO_ANALYZE.includes(node.tagName.toLowerCase())) {
        const parent = node.parentNode;
        const nextSibling = node.nextSibling;
        node.remove(); // Detach from DOM

        chrome.runtime.sendMessage(
          { action: 'analyze_element', tag: node.tagName.toLowerCase(), html: node.outerHTML },
          (response) => {
            if (!response?.malicious) {
              // Reinsert safe dynamic elements
              if (node.tagName.toLowerCase() === 'script') {
                const newScript = document.createElement('script');
                newScript.textContent = node.textContent;
                Array.from(node.attributes).forEach(attr => {
                  newScript.setAttribute(attr.name, attr.value);
                });
                parent.insertBefore(newScript, nextSibling);
              } else {
                parent.insertBefore(node, nextSibling);
              }
            }
          }
        );
      }
    });
  });
}).observe(document.documentElement, { childList: true, subtree: true });

// Start
freezeExecution();
analyzePage();