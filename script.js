const background = document.querySelector(".background-animations");

if (background) {
    for (let index = 0; index < 40; index++) {
        const ball = document.createElement("div");
        const size = Math.random() * 8 + 3;

        ball.classList.add("background-ball");
        ball.style.width = `${size}px`;
        ball.style.height = `${size}px`;
        ball.style.left = `${Math.random() * 100}%`;
        ball.style.top = `${Math.random() * 200 - 100}vh`;
        ball.style.animationDuration = `${Math.random() * 15 + 10}s`;
        ball.style.animationDelay = `${Math.random() * -20}s`;
        ball.style.opacity = `${Math.random() * 0.5 + 0.3}`;
        background.appendChild(ball);
    }
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: { "Content-Type": "application/json", ...options.headers },
        credentials: "same-origin",
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Something went wrong.");
    return result;
}

document.querySelectorAll("[data-auth-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const status = form.querySelector("[data-form-status]");
        const button = form.querySelector("button[type='submit']");
        const payload = Object.fromEntries(new FormData(form));
        status.textContent = "";
        status.classList.remove("is-error");
        button.disabled = true;

        try {
            await requestJson(`/api/${form.dataset.authForm}`, {
                method: "POST",
                body: JSON.stringify(payload),
            });
            window.location.assign("chat.html");
        } catch (error) {
            status.textContent = error.message;
            status.classList.add("is-error");
        } finally {
            button.disabled = false;
        }
    });
});

function setAvatar(wrapper, profile) {
    const image = wrapper.querySelector("img");
    const fallback = wrapper.querySelector("[data-avatar-fallback], [data-preview-fallback]");
    fallback.textContent = profile.username.slice(0, 1).toUpperCase();
    image.hidden = false;
    image.onerror = () => { image.hidden = true; };
    image.src = profile.avatar_url || "assets/profile-placeholder.png";
}

const profileForm = document.querySelector("[data-profile-form]");
if (profileForm) {
    const profileStatus = document.querySelector("[data-profile-status]");
    const profileAvatar = document.querySelector("[data-profile-avatar]");
    const fileInput = profileForm.elements.avatar;
    const removePicture = document.querySelector("[data-remove-picture]");
    let removeCurrentPicture = false;

    loadCurrentUser().then(async (user) => {
        if (!user) return window.location.assign("login.html");
        document.querySelector("[data-current-username]").textContent = user.username;
        try {
            const result = await requestJson("/api/profile");
            const profile = result.profile;
            profileForm.elements.bio.value = profile.bio;
            document.querySelector("[data-profile-email]").textContent = result.email;
            setAvatar(profileAvatar, profile);
            fileInput.disabled = !profile.photo_eligible;
            profileForm.querySelector(`label[for="${fileInput.id}"]`).setAttribute(
                "aria-disabled",
                String(!profile.photo_eligible),
            );
            document.querySelector("[data-photo-guidance]").textContent = profile.photo_eligible
                ? "Your profile photo is eligible to appear to other members."
                : "Profile photos are available after your account is at least one day old.";
        } catch (error) {
            profileStatus.textContent = error.message;
        }
    });

    fileInput.addEventListener("change", () => {
        const file = fileInput.files[0];
        if (!file) return;
        if (!/image\/(png|jpeg|webp)/.test(file.type) || file.size > 2_000_000) {
            profileStatus.textContent = "Choose a PNG, JPG, or WebP image smaller than 2 MB.";
            fileInput.value = "";
            return;
        }
        removeCurrentPicture = false;
        const image = profileAvatar.querySelector("img");
        image.src = URL.createObjectURL(file);
        image.hidden = false;
    });

    removePicture.addEventListener("click", () => {
        fileInput.value = "";
        removeCurrentPicture = true;
        profileAvatar.querySelector("img").hidden = true;
    });

    profileForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = profileForm.querySelector("button[type='submit']");
        const file = fileInput.files[0];
        const save = async (avatarData) => requestJson("/api/profile", {
            method: "POST",
            body: JSON.stringify({
                bio: profileForm.elements.bio.value,
                avatar_data: avatarData,
                remove_picture: removeCurrentPicture,
            }),
        });
        button.disabled = true;
        profileStatus.textContent = "";
        try {
            let avatarData = null;
            if (file) {
                avatarData = await new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onload = () => resolve(reader.result);
                    reader.onerror = () => reject(new Error("The selected image could not be read."));
                    reader.readAsDataURL(file);
                });
            }
            const result = await save(avatarData);
            removeCurrentPicture = false;
            fileInput.value = "";
            setAvatar(profileAvatar, result.profile);
            profileStatus.textContent = "Profile saved.";
        } catch (error) {
            profileStatus.textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
}

async function loadCurrentUser() {
    try {
        return (await requestJson("/api/me")).user;
    } catch {
        return null;
    }
}

async function initializeAdminConsole() {
    const mount = document.querySelector("[data-admin-console]");
    if (!mount) return;
    let access;
    try {
        access = await requestJson("/api/admin/status");
        if (!access.is_admin) return;
    } catch {
        return;
    }

    mount.hidden = false;
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    const badge = document.createElement("span");
    const output = document.createElement("pre");
    const form = document.createElement("form");
    const input = document.createElement("input");
    const submit = document.createElement("button");

    details.className = "admin-console-shell";
    summary.textContent = "Moderation console";
    badge.className = "admin-console-badge";
    badge.textContent = access.role.name;
    badge.style.color = access.role.color;
    summary.append(badge);
    output.className = "admin-console-output";
    output.dataset.adminOutput = "";
    output.setAttribute("aria-live", "polite");
    output.textContent = "Admin moderation ready. Type /help for commands.";
    form.className = "admin-console-form";
    input.name = "command";
    input.type = "text";
    input.maxLength = 300;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.placeholder = "/ban username reason";
    input.setAttribute("aria-label", "Admin moderation command");
    submit.type = "submit";
    submit.textContent = "Run";
    form.append(input, submit);
    details.append(summary, output, form);
    mount.appendChild(details);

    details.addEventListener("toggle", () => {
        if (details.open) input.focus();
    });
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const command = input.value.trim();
        if (!command) return;
        submit.disabled = true;
        try {
            const result = await requestJson("/api/admin/command", {
                method: "POST",
                body: JSON.stringify({ command }),
            });
            output.textContent += `\n> ${command}\n${result.output}\n`;
            input.value = "";
        } catch (error) {
            output.textContent += `\n> ${command}\nError: ${error.message}\n`;
        } finally {
            output.scrollTop = output.scrollHeight;
            submit.disabled = false;
            input.focus();
        }
    });
}

loadCurrentUser().then((user) => {
    const homeLink = document.querySelector("[data-home-link]");
    const signupLink = document.querySelector("[data-signup-link]");
    if (user && homeLink && signupLink) {
        homeLink.href = "chat.html";
        homeLink.textContent = user.username;
        signupLink.hidden = true;
    }
});

const chatForm = document.querySelector("[data-chat-form]");
if (chatForm) {
    const messageList = document.querySelector("[data-message-list]");
    const chatStatus = document.querySelector("[data-chat-status]");
    const onlineList = document.querySelector("[data-online-list]");
    const onlineCount = document.querySelector("[data-online-count]");
    const onlineStatus = document.querySelector("[data-online-status]");
    const profileOverlay = document.querySelector("[data-profile-overlay]");
    const roomGroups = document.querySelector("[data-room-groups]");
    const activeRoomTitle = document.querySelector("[data-active-room]");
    let activeRoom = "everyone";
    let lastMessageId = 0;
    let isFirstLoad = true;

    function renderMessage(message) {
        const item = document.createElement("article");
        const metadata = document.createElement("div");
        const username = document.createElement("button");
        const roleLabel = document.createElement("span");
        const time = document.createElement("time");
        const body = document.createElement("p");

        item.className = "chat-message";
        metadata.className = "message-meta";
        username.className = "message-username";
        username.type = "button";
        username.dataset.profileTrigger = message.username;
        username.textContent = message.username;
        if (message.role) {
            username.style.color = message.role.color;
            roleLabel.className = "message-role";
            roleLabel.textContent = message.role.name;
            roleLabel.style.color = message.role.color;
            roleLabel.style.borderColor = `${message.role.color}55`;
        }
        time.dateTime = message.created_at;
        time.textContent = new Date(message.created_at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
        body.className = "message-body";
        body.textContent = message.body;
        metadata.append(username);
        if (message.role) metadata.append(roleLabel);
        metadata.append(time);
        item.append(metadata, body);
        messageList.appendChild(item);
        lastMessageId = Math.max(lastMessageId, message.id);
    }

    async function refreshMessages() {
        try {
            const result = await requestJson(`/api/messages?room=${encodeURIComponent(activeRoom)}&after=${isFirstLoad ? 0 : lastMessageId}`);
            if (isFirstLoad) messageList.replaceChildren();
            result.messages.forEach(renderMessage);
            if (result.messages.length) messageList.scrollTop = messageList.scrollHeight;
            isFirstLoad = false;
            chatStatus.textContent = "";
        } catch (error) {
            chatStatus.textContent = error.message;
            if (error.message.includes("sign in")) window.location.assign("login.html");
        }
    }

    async function loadRoomGroups() {
        try {
            const result = await requestJson("/api/rooms");
            roomGroups.replaceChildren();
            result.groups.forEach((group) => {
                const details = document.createElement("details");
                const summary = document.createElement("summary");
                const roomList = document.createElement("div");

                details.className = "room-group";
                details.open = group.name === "Community" || group.name === "Tech";
                summary.textContent = group.name;
                roomList.className = "room-list";
                group.rooms.forEach((room) => {
                    const button = document.createElement("button");
                    button.type = "button";
                    button.className = "room-link";
                    button.dataset.roomId = room.id;
                    button.textContent = room.name;
                    button.classList.toggle("is-active", room.id === activeRoom);
                    button.setAttribute("aria-current", room.id === activeRoom ? "true" : "false");
                    roomList.appendChild(button);
                });
                details.append(summary, roomList);
                roomGroups.appendChild(details);
            });
        } catch (error) {
            chatStatus.textContent = error.message;
        }
    }

    roomGroups.addEventListener("click", (event) => {
        const roomButton = event.target.closest("[data-room-id]");
        if (!roomButton || roomButton.dataset.roomId === activeRoom) return;
        activeRoom = roomButton.dataset.roomId;
        activeRoomTitle.textContent = roomButton.textContent;
        roomGroups.querySelectorAll("[data-room-id]").forEach((button) => {
            const selected = button === roomButton;
            button.classList.toggle("is-active", selected);
            button.setAttribute("aria-current", selected ? "true" : "false");
        });
        lastMessageId = 0;
        isFirstLoad = true;
        messageList.replaceChildren();
        refreshMessages();
    });

    function renderOnlineUsers(users) {
        onlineList.replaceChildren();
        onlineCount.textContent = String(users.length);
        if (!users.length) {
            const empty = document.createElement("p");
            empty.className = "online-empty";
            empty.textContent = "No one else is online yet.";
            onlineList.appendChild(empty);
            return;
        }
        users.forEach((user) => {
            const button = document.createElement("button");
            const avatar = document.createElement("span");
            const fallback = document.createElement("span");
            const image = document.createElement("img");
            const name = document.createElement("span");
            const copy = document.createElement("span");
            const role = document.createElement("span");

            button.className = "online-user";
            button.type = "button";
            button.dataset.profileTrigger = user.username;
            avatar.className = "avatar avatar-small";
            fallback.dataset.avatarFallback = "";
            image.alt = "";
            name.className = "online-username";
            name.textContent = user.username;
            copy.className = "online-user-copy";
            role.className = "online-user-role";
            if (user.role) {
                name.style.color = user.role.color;
                role.textContent = user.role.name;
                role.style.color = user.role.color;
            } else {
                role.hidden = true;
            }
            avatar.append(fallback, image);
            copy.append(name, role);
            button.append(avatar, copy);
            onlineList.appendChild(button);
            setAvatar(avatar, user);
        });
    }

    async function refreshOnlineUsers() {
        try {
            const result = await requestJson("/api/presence", { method: "POST", body: "{}" });
            renderOnlineUsers(result.users);
            onlineStatus.textContent = "";
        } catch (error) {
            onlineStatus.textContent = error.message;
            if (error.message.includes("sign in")) window.location.assign("login.html");
        }
    }

    async function openProfilePreview(username) {
        try {
            const result = await requestJson(`/api/users/${encodeURIComponent(username)}`);
            const profile = result.profile;
            document.querySelector("[data-preview-username]").textContent = profile.username;
            document.querySelector("[data-preview-bio]").textContent = profile.bio || "No bio added yet.";
            const roleLabel = document.querySelector("[data-preview-role]");
            roleLabel.hidden = !profile.role;
            roleLabel.textContent = profile.role ? profile.role.name : "";
            roleLabel.style.color = profile.role ? profile.role.color : "";
            document.querySelector("[data-preview-message-count]").textContent = new Intl.NumberFormat().format(profile.message_count || 0);
            document.querySelector("[data-preview-joined]").textContent = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeZone: "UTC" }).format(new Date(profile.created_at));
            setAvatar(profileOverlay.querySelector(".avatar"), profile);
            profileOverlay.hidden = false;
        } catch (error) {
            chatStatus.textContent = error.message;
        }
    }

    document.addEventListener("click", (event) => {
        const trigger = event.target.closest("[data-profile-trigger]");
        if (trigger) {
            event.preventDefault();
            openProfilePreview(trigger.dataset.profileTrigger);
            return;
        }
        if (!profileOverlay.hidden) profileOverlay.hidden = true;
    });

    profileOverlay.addEventListener("click", () => { profileOverlay.hidden = true; });
    document.querySelector("[data-preview-close]").addEventListener("click", () => { profileOverlay.hidden = true; });
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") profileOverlay.hidden = true;
    });

    chatForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const input = chatForm.elements.message;
        const button = chatForm.querySelector("button[type='submit']");
        const message = input.value.trim();
        if (!message) return;
        button.disabled = true;
        try {
            const result = await requestJson("/api/messages", {
                method: "POST",
                body: JSON.stringify({ message, room: activeRoom }),
            });
            renderMessage(result.message);
            messageList.scrollTop = messageList.scrollHeight;
            input.value = "";
            chatStatus.textContent = "";
        } catch (error) {
            chatStatus.textContent = error.message;
        } finally {
            button.disabled = false;
            input.focus();
        }
    });

    document.querySelector("[data-logout]").addEventListener("click", async () => {
        await requestJson("/api/logout", { method: "POST", body: "{}" });
        window.location.assign("index.html");
    });

    loadCurrentUser().then((user) => {
        if (!user) return window.location.assign("login.html");
        document.querySelector("[data-current-username]").textContent = user.username;
        document.querySelector("[data-welcome-username]").textContent = user.username;
    });

    initializeAdminConsole();
    refreshMessages();
    loadRoomGroups();
    refreshOnlineUsers();
    window.setInterval(refreshMessages, 2500);
    window.setInterval(refreshOnlineUsers, 20_000);
}