// cmd/control/web/app.js

let pcPub = null;  // publishes local media
let pcSub = null;  // receives loopback media
let ws = null;
let dc = null;
let roomId = null;
let localStream = null;
let joined = false;

const joinBtn = document.getElementById('joinBtn');
const logEl = document.getElementById('log');
const roomInfoEl = document.getElementById('roomInfo');
const chatEl = document.getElementById('chat');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const localVideo = document.getElementById('localVideo');
const remoteVideo = document.getElementById('remoteVideo');

function log(msg) {
    console.log(msg);
    logEl.textContent += msg + "\n";
    logEl.scrollTop = logEl.scrollHeight;
}

async function createRoom() {
    return "room-1";
}

async function getLocalMedia() {
    if (localStream) return localStream;

    log("Requesting local media...");
    localStream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true,
    });

    localVideo.srcObject = localStream;
    localVideo.muted = true;
    await localVideo.play().catch(() => {
        log("Local video play() blocked by browser; user interaction may be required.");
    });

    log("Got local media");
    return localStream;
}

function createPeerConnections() {
    const config = {
        iceServers: [
            // { urls: "stun:stun.l.google.com:19302" },
        ],
    };

    pcPub = new RTCPeerConnection(config);
    pcSub = new RTCPeerConnection(config);

    // Publisher PC ICE
    pcPub.onicecandidate = (event) => {
        if (event.candidate) {
            log("Sending publisher ICE candidate");
            ws.send(JSON.stringify({
                type: "candidate",
                role: "publisher",
                candidate: event.candidate,
            }));
        }
    };

    pcPub.onconnectionstatechange = () => {
        log("pcPub state: " + pcPub.connectionState);
        if (pcPub.connectionState === "connected") {
            chatEl.style.display = "block";
        }
    };

    // Subscriber PC ICE
    pcSub.onicecandidate = (event) => {
        if (event.candidate) {
            log("Sending subscriber ICE candidate");
            ws.send(JSON.stringify({
                type: "candidate",
                role: "subscriber",
                candidate: event.candidate,
            }));
        }
    };

    pcSub.onconnectionstatechange = () => {
        log("pcSub state: " + pcSub.connectionState);
    };

    // Remote loopback tracks arrive on pcSub
    pcSub.ontrack = (event) => {
        log("pcSub received remote track: kind=" + event.track.kind +
            " streams=" + event.streams.length);

        if (event.streams && event.streams[0]) {
            remoteVideo.srcObject = event.streams[0];
        } else {
            if (!remoteVideo.srcObject) {
                remoteVideo.srcObject = new MediaStream();
            }
            remoteVideo.srcObject.addTrack(event.track);
        }

        // make sure it's muted before trying to play
        remoteVideo.muted = true;

        if (remoteVideo.paused) {
            remoteVideo.play().catch((err) => {
                log("Remote video play() failed: " + err.name + " " + err.message);
            });
        }
    };


    // DataChannel on publisher PC
    dc = pcPub.createDataChannel("echo");
    dc.onopen = () => log("DataChannel open (pcPub)");
    dc.onmessage = (event) => {
        log("DataChannel message from server: " + event.data);
    };
}

async function joinRoom() {
    if (joined) {
        log("Already joined; ignoring second click.");
        return;
    }
    joined = true;
    joinBtn.disabled = true;

    try {
        roomId = await createRoom();
        roomInfoEl.textContent = `Room ID: ${roomId}`;
        log(`Created/Joined room ${roomId}`);

        // Open WebSocket
        const wsUrl = (() => {
            const proto = location.protocol === "https:" ? "wss" : "ws";
            return `${proto}://${location.host}/signal?room_id=${encodeURIComponent(roomId)}`;
        })();

        ws = new WebSocket(wsUrl);

        ws.onopen = () => log("WebSocket connected");

        ws.onmessage = async (event) => {
            const msg = JSON.parse(event.data);

            if (msg.type === "answer" && msg.role === "publisher") {
                // Answer to our initial publish offer
                log("Received answer (publisher)");
                await pcPub.setRemoteDescription({
                    type: "answer",
                    sdp: msg.sdp,
                });

            } else if (msg.type === "offer" && msg.role === "subscriber") {
                // SFU's subscriber PC is offering us loopback media
                log("Received offer (subscriber), signalingState=" + pcSub.signalingState);

                try {
                    if (pcSub.signalingState !== "stable") {
                        log("pcSub not stable (" + pcSub.signalingState + "), skipping offer.");
                        return;
                    }

                    await pcSub.setRemoteDescription({
                        type: "offer",
                        sdp: msg.sdp,
                    });

                    const answer = await pcSub.createAnswer();
                    await pcSub.setLocalDescription(answer);

                    log("Sending answer (subscriber)");
                    ws.send(JSON.stringify({
                        type: "answer",
                        role: "subscriber",
                        sdp: answer.sdp,
                    }));
                } catch (err) {
                    log("Error handling subscriber offer: " + err);
                }

            } else if (msg.type === "candidate" && msg.role === "publisher") {
                if (msg.candidate) {
                    log("Received ICE candidate (publisher)");
                    try {
                        await pcPub.addIceCandidate(msg.candidate);
                    } catch (err) {
                        log("Error adding publisher ICE candidate: " + err);
                    }
                }

            } else if (msg.type === "candidate" && msg.role === "subscriber") {
                if (msg.candidate) {
                    log("Received ICE candidate (subscriber)");
                    try {
                        await pcSub.addIceCandidate(msg.candidate);
                    } catch (err) {
                        log("Error adding subscriber ICE candidate: " + err);
                    }
                }

            } else {
                log("Unknown message from server: " + event.data);
            }
        };

        ws.onclose = () => log("WebSocket closed");
        ws.onerror = (err) => log("WebSocket error: " + err);

        await new Promise((resolve, reject) => {
            ws.addEventListener("open", resolve, { once: true });
            ws.addEventListener("error", reject, { once: true });
        });

        // Create PCs & publish local media on pcPub
        createPeerConnections();
        const stream = await getLocalMedia();
        stream.getTracks().forEach((track) => {
            pcPub.addTrack(track, stream);
        });

        // Initial offer as publisher
        if (pcPub.signalingState === "stable") {
            log("Creating publisher offer");
            const offer = await pcPub.createOffer();
            await pcPub.setLocalDescription(offer);

            log("Sending offer (publisher)");
            ws.send(JSON.stringify({
                type: "offer",
                role: "publisher",
                sdp: offer.sdp,
            }));
        }

    } catch (err) {
        log("Error: " + err);
        joinBtn.disabled = false;
        joined = false;
    }
}

joinBtn.addEventListener("click", () => {
    joinRoom();
});

sendBtn.addEventListener("click", () => {
    const text = messageInput.value;
    if (!text || !dc || dc.readyState !== "open") {
        return;
    }
    dc.send(text);
    log("Sent via DataChannel: " + text);
    messageInput.value = "";
});
