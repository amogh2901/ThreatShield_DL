chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

    if (changeInfo.status !== "complete" || !tab.url)
        return;

    if (
        tab.url.startsWith("chrome://") ||
        tab.url.startsWith("chrome-extension://") ||
        tab.url.startsWith("edge://")
    )
        return;

    fetch("http://127.0.0.1:5000/analyze", {

        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify({
            url: tab.url
        })

    })

    .then(res => res.json())

    .then(data => {

        let reason = encodeURIComponent(data.attack);
        let original = encodeURIComponent(tab.url);

        if(data.attack !== "normal"){

            chrome.notifications.create({

                type: "basic",

                iconUrl: "icon.png",

                title: "ThreatShield",

                message: data.attack.toUpperCase()+" detected"

            });

        }

        if(data.severity==="HIGH" && data.attack!=="normal"){

            chrome.tabs.update(tabId,{

                url:
                chrome.runtime.getURL("blocked.html")+
                "?reason="+reason+
                "&url="+original

            });

        }

    })

    .catch(err=>{

        console.log("ThreatShield Error",err);

    });

});
