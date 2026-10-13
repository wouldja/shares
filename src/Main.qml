import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

ApplicationWindow {
    id: win
    width: 1200
    height: 760
    minimumWidth: 960
    minimumHeight: 640
    visible: true
    title: "shares"
    color: "#16161e"

    Material.theme: Material.Dark
    Material.accent: theme.accent

    font.family: "JetBrainsMono NF"
    font.pixelSize: 12

    property bool helpOpen: false
    property bool createOpen: false
    property bool removeOpen: false
    property bool passwordsOpen: false
    property bool editorOpen: false
    property bool globalOpen: false
    property bool importOpen: false
    property bool quitOpen: false
    property bool hostsOpen: false
    property bool needsOpen: false
    property bool leaveOpen: false
    property int hostCursor: 0
    property int hostFieldFocus: 0
    readonly property bool typing: filterField.activeFocus || nameField.activeFocus || pathField.activeFocus
        || editorField.activeFocus || globalField.activeFocus || importField.activeFocus
        || accountField.activeFocus || secretField.activeFocus || serviceField.activeFocus
        || hostUserField.activeFocus || hostNameField.activeFocus || hostPortField.activeFocus
        || remoteFolderField.activeFocus || remoteImageField.activeFocus
        || hostFieldFocus > 0
    readonly property bool overlay: helpOpen || createOpen || removeOpen || passwordsOpen || editorOpen || globalOpen || importOpen || quitOpen || hostsOpen || needsOpen || leaveOpen
    property int browseCursor: 0
    readonly property bool letters: !overlay && !typing

    function closeOverlays() {
        helpOpen = false
        createOpen = false
        removeOpen = false
        passwordsOpen = false
        editorOpen = false
        globalOpen = false
        importOpen = false
        quitOpen = false
        hostsOpen = false
        needsOpen = false
        leaveOpen = false
    }

    function requestDisconnect() {
        if (!backend.remote) {
            hostsOpen = false
            return
        }
        hostsOpen = false
        needsOpen = false
        helpOpen = false
        if (backend.canUndo) {
            leaveOpen = true
            return
        }
        finishDisconnect()
    }

    function finishDisconnect() {
        backend.leaveComputer()
        leaveOpen = false
        hostsOpen = false
        needsOpen = false
        helpOpen = false
    }

    function saveAndLeave() {
        if (backend.save())
            finishDisconnect()
    }

    function requestQuit() {
        if (backend.dirty)
            quitOpen = true
        else
            Qt.quit()
    }

    function saveAndQuit() {
        if (backend.save())
            Qt.quit()
        quitOpen = false
    }

    function openEditor() {
        editorField.text = backend.editorText()
        editorOpen = true
        editorField.forceActiveFocus()
    }

    function openGlobal() {
        globalField.text = backend.globalText()
        globalOpen = true
        globalField.forceActiveFocus()
    }

    function openImport() {
        importField.text = backend.exportText()
        importOpen = true
        importField.forceActiveFocus()
    }

    function applyPassword() {
        var ok = false
        if (backend.protocol === 3)
            ok = backend.createAccess(serviceField.text, accountField.text, secretField.text)
        else
            ok = backend.setSambaPassword(accountField.text, secretField.text)
        if (ok)
            secretField.text = ""
    }

    function removePassword() {
        if (backend.protocol === 3)
            backend.removeAccess(serviceField.text, accountField.text)
        else
            backend.removeSambaPassword(accountField.text)
    }

    function applyEditorAndClose() {
        if (backend.applyEditor(editorField.text))
            editorOpen = false
    }

    function applyGlobalAndClose() {
        if (backend.applyGlobal(globalField.text))
            globalOpen = false
    }

    function importAndClose() {
        if (backend.importText(importField.text))
            importOpen = false
    }

    function copyImport() {
        importField.selectAll()
        importField.copy()
    }

    function openCreate() {
        backend.clearError()
        createOpen = true
        if (backend.protocol === 3)
            nameField.forceActiveFocus()
        else
            browseForCreate()
    }

    function browseForCreate() {
        backend.browseForCreate(pathField.text, nameField.text)
    }

    function makeRemoteFolder() {
        if (backend.browseMake(remoteFolderField.text))
            remoteFolderField.text = ""
    }

    function moveBrowse(delta) {
        var count = backend.browseRows.length
        if (count < 1)
            return
        browseCursor = (browseCursor + delta + count) % count
        var y = browseCursor * 32
        if (y < browseFlick.contentY)
            browseFlick.contentY = y
        else if (y + 32 > browseFlick.contentY + browseFlick.height)
            browseFlick.contentY = y + 32 - browseFlick.height
    }

    function usePickedPath(path) {
        pathField.text = path
        if (nameField.text.trim() === "" && backend.protocol !== 1) {
            var base = path.substring(path.lastIndexOf("/") + 1)
            if (base.endsWith(".img"))
                base = base.substring(0, base.length - 4)
            nameField.text = base
        }
        if (backend.protocol === 1)
            pathField.forceActiveFocus()
        else
            nameField.forceActiveFocus()
    }

    function clearFilter() {
        filterField.text = ""
        backend.filter = ""
        filterField.focus = false
    }

    function openHosts() {
        backend.refreshHosts()
        hostCursor = 0
        hostsOpen = true
    }

    function moveHost(delta) {
        var count = backend.hosts.length
        if (count < 1)
            return
        hostCursor = (hostCursor + delta + count) % count
    }

    function connectTypedHost() {
        backend.addHost(hostUserField.text, hostNameField.text, parseInt(hostPortField.text))
    }

    function activateHost() {
        var naming = hostUserField.activeFocus || hostNameField.activeFocus || hostPortField.activeFocus
        if (naming && hostNameField.text.trim() !== "") {
            connectTypedHost()
            return
        }
        if (hostCursor < 0 || hostCursor >= backend.hosts.length)
            return
        var row = backend.hosts[hostCursor]
        if (row.id === "local") {
            requestDisconnect()
            return
        }
        if (row.via === "tailscale")
            backend.useHost(row.id)
        else
            backend.useHost(row.id, hostUserField.text)
    }

    Shortcut { sequence: "?"; context: Qt.ApplicationShortcut; enabled: !typing; onActivated: helpOpen = !helpOpen }
    Shortcut { sequence: "Q"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: requestQuit() }
    Shortcut { sequence: "Esc"; context: Qt.ApplicationShortcut; enabled: backend.browsing && backend.remote; onActivated: backend.browseCancel() }
    Shortcut { sequence: "Esc"; context: Qt.ApplicationShortcut; enabled: overlay && !backend.browsing; onActivated: closeOverlays() }
    Shortcut { sequence: "J"; context: Qt.ApplicationShortcut; enabled: backend.browsing && backend.remote && !typing; onActivated: moveBrowse(1) }
    Shortcut { sequence: "K"; context: Qt.ApplicationShortcut; enabled: backend.browsing && backend.remote && !typing; onActivated: moveBrowse(-1) }
    Shortcut { sequence: "Down"; context: Qt.ApplicationShortcut; enabled: backend.browsing && backend.remote && !typing; onActivated: moveBrowse(1) }
    Shortcut { sequence: "Up"; context: Qt.ApplicationShortcut; enabled: backend.browsing && backend.remote && !typing; onActivated: moveBrowse(-1) }
    Shortcut { sequence: "Return"; context: Qt.ApplicationShortcut; enabled: backend.browsing && backend.remote && !typing; onActivated: backend.browseEnter(browseCursor) }
    Shortcut { sequence: "Enter"; context: Qt.ApplicationShortcut; enabled: backend.browsing && backend.remote && !typing; onActivated: backend.browseEnter(browseCursor) }
    Shortcut { sequence: "1"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.setProtocol(0) }
    Shortcut { sequence: "2"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.setProtocol(1) }
    Shortcut { sequence: "3"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.setProtocol(2) }
    Shortcut { sequence: "4"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.setProtocol(3) }
    Shortcut { sequence: "E"; context: Qt.ApplicationShortcut; enabled: letters && backend.hasSelection; onActivated: openEditor() }
    Shortcut { sequence: "G"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: openGlobal() }
    Shortcut { sequence: "I"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: openImport() }
    Shortcut { sequence: "Ctrl+S"; context: Qt.ApplicationShortcut; enabled: !overlay; onActivated: backend.save() }
    Shortcut { sequence: "J"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.move(1) }
    Shortcut { sequence: "K"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.move(-1) }
    Shortcut { sequence: "Down"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.move(1) }
    Shortcut { sequence: "Up"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.move(-1) }
    Shortcut { sequence: "Space"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.toggleEnabled() }
    Shortcut { sequence: "C"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: backend.copyAddress() }
    Shortcut { sequence: "N"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: openCreate() }
    Shortcut { sequence: "H"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: openHosts() }
    Shortcut {
        sequence: "X"
        context: Qt.ApplicationShortcut
        enabled: backend.remote && !typing && !createOpen && !removeOpen && !passwordsOpen && !editorOpen && !globalOpen && !importOpen && !quitOpen && !leaveOpen
        onActivated: requestDisconnect()
    }
    Shortcut { sequence: "X"; context: Qt.ApplicationShortcut; enabled: leaveOpen; onActivated: finishDisconnect() }
    Shortcut { sequence: "Return"; context: Qt.ApplicationShortcut; enabled: leaveOpen; onActivated: saveAndLeave() }
    Shortcut { sequence: "Enter"; context: Qt.ApplicationShortcut; enabled: leaveOpen; onActivated: saveAndLeave() }
    Shortcut { sequence: "J"; context: Qt.ApplicationShortcut; enabled: hostsOpen && !typing; onActivated: moveHost(1) }
    Shortcut { sequence: "K"; context: Qt.ApplicationShortcut; enabled: hostsOpen && !typing; onActivated: moveHost(-1) }
    Shortcut { sequence: "Down"; context: Qt.ApplicationShortcut; enabled: hostsOpen && !typing; onActivated: moveHost(1) }
    Shortcut { sequence: "Up"; context: Qt.ApplicationShortcut; enabled: hostsOpen && !typing; onActivated: moveHost(-1) }
    Shortcut { sequence: "Return"; context: Qt.ApplicationShortcut; enabled: hostsOpen && hostFieldFocus === 0; onActivated: activateHost() }
    Shortcut { sequence: "Enter"; context: Qt.ApplicationShortcut; enabled: hostsOpen && hostFieldFocus === 0; onActivated: activateHost() }
    Shortcut { sequence: "D"; context: Qt.ApplicationShortcut; enabled: letters && backend.hasSelection; onActivated: removeOpen = true }
    Shortcut { sequence: "U"; context: Qt.ApplicationShortcut; enabled: letters; onActivated: passwordsOpen = true }
    Shortcut { sequence: "/"; context: Qt.ApplicationShortcut; enabled: !overlay && !filterField.activeFocus; onActivated: filterField.forceActiveFocus() }
    Shortcut { sequence: "Ctrl+Z"; context: Qt.ApplicationShortcut; enabled: !typing && !createOpen && !removeOpen; onActivated: backend.undo() }
    Shortcut { sequence: "Ctrl+Shift+Z"; context: Qt.ApplicationShortcut; enabled: !typing && !createOpen && !removeOpen; onActivated: backend.redo() }
    Shortcut { sequence: "Return"; context: Qt.ApplicationShortcut; enabled: createOpen && !backend.browsing; onActivated: confirmCreate() }
    Shortcut { sequence: "Enter"; context: Qt.ApplicationShortcut; enabled: createOpen && !backend.browsing; onActivated: confirmCreate() }
    Shortcut { sequence: "Ctrl+O"; context: Qt.ApplicationShortcut; enabled: createOpen && !backend.browsing && backend.protocol !== 3; onActivated: browseForCreate() }
    Shortcut { sequence: "Return"; context: Qt.ApplicationShortcut; enabled: removeOpen; onActivated: confirmRemove() }
    Shortcut { sequence: "Enter"; context: Qt.ApplicationShortcut; enabled: removeOpen; onActivated: confirmRemove() }

    function confirmCreate() {
        if (backend.create(nameField.text, pathField.text)) {
            nameField.text = ""
            pathField.text = ""
            createOpen = false
        }
    }

    function confirmRemove() {
        backend.removeSelected()
        removeOpen = false
    }

    component Keycap: Rectangle {
        property string label: ""
        width: Math.max(16, cap.implicitWidth + 8)
        height: 16
        color: "#0f0f18"
        border.color: "#424247"
        border.width: 1
        Text { id: cap; anchors.centerIn: parent; text: label; color: "#bcbec8"; font.pixelSize: 11; font.bold: true; font.family: win.font.family }
    }

    component ActionButton: Rectangle {
        property string label: ""
        property string key: ""
        property bool primary: false
        property bool danger: false
        signal activated()
        width: row.implicitWidth + 20
        height: 28
        color: "transparent"
        border.width: 1
        border.color: danger ? "#a17675" : primary ? theme.accent : "#424247"
        Row {
            id: row
            anchors.centerIn: parent
            spacing: 8
            Text {
                text: label
                color: parent.parent.danger ? "#a17675" : parent.parent.primary ? theme.accent : "#bcbec8"
                font.family: win.font.family
                font.pixelSize: 12
            }
            Keycap { label: key; visible: key !== "" }
        }
        MouseArea { anchors.fill: parent; onClicked: parent.activated() }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 42
            color: "#16161e"
            Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }
            Row {
                anchors.left: parent.left
                anchors.leftMargin: 16
                anchors.verticalCenter: parent.verticalCenter
                spacing: 10
                Text { text: "shares"; color: "#bcbec8"; font.bold: true; font.family: win.font.family }
                Text { text: backend.hostTitle; color: "#7e8089"; font.family: win.font.family }
                Item {
                    width: hostRow.implicitWidth
                    height: hostRow.implicitHeight
                    Row {
                        id: hostRow
                        spacing: 6
                        Keycap { label: "H" }
                        Text { anchors.verticalCenter: parent.verticalCenter; text: "computers"; color: "#7e8089"; font.family: win.font.family }
                    }
                    MouseArea { anchors.fill: parent; onClicked: win.openHosts() }
                }
            }
            Row {
                anchors.right: parent.right
                anchors.rightMargin: 14
                anchors.verticalCenter: parent.verticalCenter
                spacing: 14
                Item {
                    width: backend.remote ? discRow.implicitWidth : 0
                    height: discRow.implicitHeight
                    visible: backend.remote
                    Row {
                        id: discRow
                        spacing: 6
                        Keycap { label: "X" }
                        Text { anchors.verticalCenter: parent.verticalCenter; text: "disconnect"; color: "#7e8089"; font.family: win.font.family }
                    }
                    MouseArea { anchors.fill: parent; onClicked: win.requestDisconnect() }
                }
                Row {
                    spacing: 6
                    Keycap { label: "?" }
                    Text { anchors.verticalCenter: parent.verticalCenter; text: "keys"; color: "#7e8089"; font.family: win.font.family }
                }
                Row {
                    spacing: 6
                    Keycap { label: "Q" }
                    Text { anchors.verticalCenter: parent.verticalCenter; text: "quit"; color: "#7e8089"; font.family: win.font.family }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            Rectangle {
                Layout.preferredWidth: 196
                Layout.fillHeight: true
                color: "#16161e"
                Rectangle { anchors.right: parent.right; width: 1; height: parent.height; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }

                Column {
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 0

                    Text { height: 32; width: parent.width; verticalAlignment: Text.AlignVCenter; leftPadding: 8; text: backend.hostTitle.toUpperCase(); color: "#7e8089"; font.bold: true; font.pixelSize: 11; font.letterSpacing: 1; font.family: win.font.family; elide: Text.ElideRight }

                    Repeater {
                        model: ["Samba", "NFS", "iSCSI", "S3"]
                        delegate: Rectangle {
                            required property int index
                            required property string modelData
                            width: 180
                            height: 28
                            color: backend.protocol === index ? Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.18) : "transparent"
                            Row {
                                anchors.fill: parent
                                anchors.leftMargin: 8
                                anchors.rightMargin: 8
                                spacing: 8
                                Rectangle { width: 6; height: 6; anchors.verticalCenter: parent.verticalCenter; color: "#73876b" }
                                Text { anchors.verticalCenter: parent.verticalCenter; text: modelData; color: backend.protocol === index ? "#bcbec8" : "#a1a3ad"; font.family: win.font.family }
                            }
                            Text { anchors.right: parent.right; anchors.rightMargin: 8; anchors.verticalCenter: parent.verticalCenter; text: backend.counts[index]; color: "#7e8089"; font.family: win.font.family }
                            MouseArea { anchors.fill: parent; onClicked: backend.setProtocol(index) }
                        }
                    }

                    Text { height: 32; width: parent.width; topPadding: 10; verticalAlignment: Text.AlignVCenter; leftPadding: 8; text: "REACHABLE AS"; color: "#7e8089"; font.bold: true; font.pixelSize: 11; font.letterSpacing: 1; font.family: win.font.family }
                    Repeater {
                        model: backend.reachable
                        delegate: Text {
                            required property string modelData
                            leftPadding: 8
                            topPadding: 4
                            width: 170
                            text: modelData
                            color: "#bcbec8"
                            wrapMode: Text.Wrap
                            font.pixelSize: 11
                            font.family: win.font.family
                        }
                    }
                    Item { width: 1; height: 72 }
                }

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    height: 78
                    color: "#16161e"
                    Rectangle { anchors.top: parent.top; width: parent.width; height: 1; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }
                    Text {
                        anchors.fill: parent
                        anchors.margins: 8
                        text: backend.protocol === 0 ? backend.foot + "\nSamba passwords  U" : backend.foot
                        color: "#7e8089"
                        font.pixelSize: 11
                        wrapMode: Text.Wrap
                        font.family: win.font.family
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumWidth: 0
                Layout.margins: 18
                Layout.bottomMargin: 8
                spacing: 8

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 10
                    // A layout ignores Text.width and sizes from the unwrapped
                    // line, which pushed Save, New, and the detail column off
                    // the window. This item takes the leftover width and the
                    // lines wrap inside it.
                    Item {
                        Layout.fillWidth: true
                        Layout.minimumWidth: 0
                        implicitHeight: heading.implicitHeight
                        Column {
                            id: heading
                            width: parent.width
                            spacing: 4
                            Text { width: parent.width; text: backend.protocolName; color: "#bcbec8"; font.pixelSize: 14; font.bold: true; font.family: win.font.family; elide: Text.ElideRight }
                            Text { width: parent.width; text: backend.subtitle; color: "#7e8089"; font.family: win.font.family; wrapMode: Text.Wrap }
                            Text {
                                visible: backend.notice !== ""
                                width: parent.width
                                text: backend.notice
                                color: "#907f63"
                                font.family: win.font.family
                                wrapMode: Text.Wrap
                                maximumLineCount: 6
                                elide: Text.ElideRight
                            }
                            Text {
                                visible: backend.error !== ""
                                width: parent.width
                                text: backend.error
                                color: "#a17675"
                                font.family: win.font.family
                                wrapMode: Text.Wrap
                                maximumLineCount: 6
                                elide: Text.ElideRight
                            }
                        }
                    }
                    ActionButton { label: "Save"; key: "S"; primary: backend.dirty; onActivated: backend.save(); Layout.alignment: Qt.AlignTop }
                    ActionButton { label: "New"; key: "N"; primary: true; onActivated: win.openCreate(); Layout.alignment: Qt.AlignTop }
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 32
                    color: "#0f0f18"
                    border.color: "#424247"
                    Row {
                        anchors.fill: parent
                        anchors.leftMargin: 10
                        anchors.rightMargin: 10
                        spacing: 8
                        Keycap { label: "/"; anchors.verticalCenter: parent.verticalCenter }
                        TextField {
                            id: filterField
                            width: parent.width - 32
                            anchors.verticalCenter: parent.verticalCenter
                            placeholderText: "Filter"
                            placeholderTextColor: "#7e8089"
                            color: "#a1a3ad"
                            font.family: win.font.family
                            font.pixelSize: 12
                            background: Item {}
                            onTextEdited: backend.filter = text
                            Keys.onEscapePressed: win.clearFilter()
                        }
                    }
                }

                Flickable {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    contentHeight: listCol.height
                    clip: true
                    Column {
                    id: listCol
                    width: parent.width
                    spacing: 0
                    Repeater {
                        model: backend.rows
                        delegate: Rectangle {
                            required property var modelData
                            width: parent.width
                            height: 52
                            color: modelData.id === backend.detail.id ? Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.18) : "transparent"
                            opacity: modelData.enabled ? 1 : 0.45
                            Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }
                            Text { x: 10; y: 8; text: modelData.name; color: modelData.id === backend.detail.id ? "#bcbec8" : "#a1a3ad"; font.family: win.font.family }
                            Text { x: 10; y: 28; text: modelData.path; color: "#7e8089"; font.family: win.font.family; width: parent.width - 140; elide: Text.ElideMiddle }
                            Row {
                                anchors.right: parent.right
                                anchors.rightMargin: 10
                                anchors.top: parent.top
                                anchors.topMargin: 8
                                spacing: 6
                                Repeater {
                                    model: modelData.badges
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: badgeText.implicitWidth + 12
                                        height: 16
                                        color: "transparent"
                                        border.width: 1
                                        border.color: modelData.warn ? "#907f63" : "#424247"
                                        Text { id: badgeText; anchors.centerIn: parent; text: modelData.text; color: parent.border.color; font.pixelSize: 11; font.family: win.font.family }
                                    }
                                }
                            }
                            Text { anchors.right: parent.right; anchors.rightMargin: 10; anchors.bottom: parent.bottom; anchors.bottomMargin: 8; text: modelData.meta; color: "#7e8089"; font.pixelSize: 11; font.family: win.font.family }
                            MouseArea { anchors.fill: parent; onClicked: backend.select(modelData.id) }
                        }
                    }
                    }
                }
            }

            Rectangle {
                Layout.preferredWidth: 340
                Layout.fillHeight: true
                color: "#16161e"
                Rectangle { anchors.left: parent.left; width: 1; height: parent.height; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }

                Flickable {
                    anchors.fill: parent
                    anchors.margins: 18
                    anchors.bottomMargin: 96
                    contentHeight: detailCol.implicitHeight
                    clip: true
                    visible: backend.hasSelection
                Column {
                    id: detailCol
                    width: 304
                    spacing: 14

                    Column {
                        spacing: 4
                        Text { text: backend.detail.name || ""; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
                        Text { text: backend.detail.path || ""; color: "#7e8089"; width: 300; wrapMode: Text.WrapAnywhere; font.family: win.font.family }
                    }

                    Column {
                        spacing: 6
                        Text { text: "ADDRESS"; color: "#7e8089"; font.pixelSize: 11; font.bold: true; font.letterSpacing: 1; font.family: win.font.family }
                        Rectangle {
                            width: 304
                            height: addressCol.implicitHeight + 16
                            color: "#0f0f18"
                            border.color: "#424247"
                            Column {
                                id: addressCol
                                x: 10
                                y: 8
                                width: 284
                                spacing: 6
                                Repeater {
                                    model: backend.detail.addresses || []
                                    delegate: Text {
                                        required property string modelData
                                        width: 284
                                        text: modelData
                                        color: "#a1a3ad"
                                        wrapMode: Text.WrapAnywhere
                                        font.family: win.font.family
                                    }
                                }
                                ActionButton { label: "Copy"; key: "C"; primary: true; onActivated: backend.copyAddress() }
                            }
                        }
                    }

                    Column {
                        width: 304
                        spacing: 0
                        Repeater {
                            model: backend.detail.switches || []
                            delegate: Item {
                                required property var modelData
                                width: 304
                                height: 28
                                Text { anchors.verticalCenter: parent.verticalCenter; text: modelData.label; color: "#a1a3ad"; font.family: win.font.family }
                                Rectangle {
                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: 42
                                    height: 22
                                    color: modelData.on ? "#3a3a46" : "#0f0f18"
                                    border.width: modelData.on ? 0 : 1
                                    border.color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.40)
                                    Rectangle {
                                        x: modelData.on ? 24 : 2
                                        y: 2
                                        width: 16
                                        height: 16
                                        color: modelData.on ? "#a1a3ad" : "#7e8089"
                                    }
                                    MouseArea { anchors.fill: parent; onClicked: backend.toggle(modelData.key) }
                                }
                            }
                        }
                    }

                    Repeater {
                        model: backend.detail.facts || []
                        delegate: Column {
                            required property var modelData
                            width: 304
                            spacing: 4
                            Text { text: modelData.label; color: "#7e8089"; font.pixelSize: 11; font.bold: true; font.letterSpacing: 1; font.family: win.font.family }
                            Text { text: modelData.value; color: "#a1a3ad"; width: 304; wrapMode: Text.WrapAnywhere; font.family: win.font.family }
                        }
                    }

                    Rectangle {
                        width: 304
                        height: 32
                        color: "transparent"
                        Rectangle { anchors.top: parent.top; width: parent.width; height: 1; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }
                        Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }
                        Text { anchors.verticalCenter: parent.verticalCenter; text: "Advanced"; color: "#a1a3ad"; font.family: win.font.family }
                        Text { anchors.right: parent.right; anchors.verticalCenter: parent.verticalCenter; text: (backend.detail.advanced || "") + " ›"; color: "#7e8089"; font.family: win.font.family }
                        MouseArea { anchors.fill: parent; onClicked: win.openEditor() }
                    }
                }
                }

                Column {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    anchors.margins: 18
                    spacing: 8
                    visible: backend.hasSelection
                    ActionButton { label: backend.removeLabel; key: "D"; danger: true; onActivated: win.removeOpen = true }
                    Text { text: backend.keptLine; color: "#7e8089"; width: 304; wrapMode: Text.Wrap; font.family: win.font.family }
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 36
            color: "#16161e"
            Rectangle { anchors.top: parent.top; width: parent.width; height: 1; color: Qt.rgba(161 / 255, 163 / 255, 173 / 255, 0.12) }
            Row {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: 16
                spacing: 16
                Row {
                    spacing: 6
                    Keycap { label: "J" }
                    Keycap { label: "K" }
                    Text { anchors.verticalCenter: parent.verticalCenter; text: "move"; color: "#7e8089"; font.family: win.font.family }
                }
                Row {
                    spacing: 6
                    Keycap { label: "1" }
                    Keycap { label: "2" }
                    Keycap { label: "3" }
                    Keycap { label: "4" }
                    Text { anchors.verticalCenter: parent.verticalCenter; text: "service"; color: "#7e8089"; font.family: win.font.family }
                }
                Row {
                    spacing: 6
                    Keycap { label: "Space" }
                    Text { anchors.verticalCenter: parent.verticalCenter; text: "enable"; color: "#7e8089"; font.family: win.font.family }
                }
                Text { anchors.verticalCenter: parent.verticalCenter; text: backend.dirty ? "unsaved" : "live"; color: backend.dirty ? "#907f63" : "#a1a3ad"; font.family: win.font.family }
            }
        }
    }

    Rectangle {
        anchors.fill: parent
        visible: win.overlay
        color: Qt.rgba(0, 0, 0, 0.60)
        MouseArea { anchors.fill: parent }
    }

    Rectangle {
        visible: win.helpOpen
        anchors.centerIn: parent
        width: 420
        height: helpCol.implicitHeight + 36
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: helpCol
            x: 18
            y: 18
            width: 384
            spacing: 8
            Text { text: "Keys"; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Repeater {
                model: [
                    "?    show or hide this list",
                    "Q    quit",
                    "1 2 3 4    Samba, NFS, iSCSI, S3",
                    "J K    move through the list",
                    "/    filter",
                    "H    computers on SSH or Tailscale",
                    "X    disconnect. X again leaves unsaved edits",
                    "N    new share. Browse lists that computer",
                    "Ctrl+O    browse again while creating",
                    "E    edit the selected row",
                    "G    Samba global settings",
                    "I    import or export",
                    "C    copy the address",
                    "Space    enable or disable",
                    "D    remove, then confirm",
                    "U    Samba passwords or S3 access",
                    "Ctrl+S    save",
                    "Ctrl+Z    undo",
                    "Ctrl+Shift+Z    redo"
                ]
                delegate: Text { required property string modelData; text: modelData; color: "#a1a3ad"; font.family: win.font.family }
            }
        }
    }

    Rectangle {
        visible: win.createOpen
        anchors.centerIn: parent
        width: 420
        height: createCol.implicitHeight + 36
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: createCol
            x: 18
            y: 18
            width: 384
            spacing: 10
            Text { text: "New " + backend.protocolName.toLowerCase(); color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 384; wrapMode: Text.Wrap; text: backend.createHint; color: "#7e8089"; font.family: win.font.family }
            TextField {
                id: nameField
                width: 384
                placeholderText: "Name"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
            }
            Row {
                spacing: 8
                TextField {
                    id: pathField
                    width: backend.protocol === 3 ? 384 : 292
                    placeholderText: backend.protocol === 2 ? "Disk image path" : backend.protocol === 3 ? "Backend" : "Folder"
                    placeholderTextColor: "#7e8089"
                    color: "#a1a3ad"
                    font.family: win.font.family
                    background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                }
                ActionButton {
                    visible: backend.protocol !== 3
                    label: "Browse"
                    onActivated: win.browseForCreate()
                }
            }
            Text {
                visible: backend.browsing && !backend.remote
                width: 384
                wrapMode: Text.Wrap
                text: "The browser is open. Create Folder makes the directory. Arrows, Enter, and the mouse all work there."
                color: "#907f63"
                font.family: win.font.family
            }
            Text { visible: backend.error !== ""; text: backend.error; color: "#a17675"; width: 384; wrapMode: Text.Wrap; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Create"; key: ""; primary: true; onActivated: win.confirmCreate() }
                ActionButton { label: "Cancel"; key: ""; onActivated: win.createOpen = false }
            }
        }
    }

    Connections {
        target: backend
        function onCreatePathChosen(path) { win.usePickedPath(path) }
        function onNeedsReady() { needsOpen = true }
        function onComputerReady() { hostsOpen = false }
        function onHostChanged() { win.hostFieldFocus = 0 }
        function onBrowseChanged() { win.browseCursor = 0; if (browseFlick) browseFlick.contentY = 0 }
    }

    Rectangle {
        visible: backend.browsing && backend.remote
        onVisibleChanged: if (visible) remoteImageField.text = backend.browseFile
        anchors.centerIn: parent
        width: 460
        height: Math.min(560, remoteBrowseCol.implicitHeight + 36)
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: remoteBrowseCol
            x: 18
            y: 18
            width: 424
            spacing: 8
            Text { text: "Folder on " + backend.hostTitle; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 424; text: backend.browsePath; color: "#a1a3ad"; font.family: win.font.family; elide: Text.ElideMiddle }
            Text { width: 424; wrapMode: Text.Wrap; text: "J and K move. Enter opens a directory. Use this folder keeps the one shown above."; color: "#7e8089"; font.family: win.font.family }
            Flickable {
                id: browseFlick
                width: 424
                height: 220
                contentHeight: browseList.implicitHeight
                clip: true
                Column {
                    id: browseList
                    width: 424
                    spacing: 0
                    Repeater {
                        model: backend.browseRows
                        delegate: Rectangle {
                            required property var modelData
                            required property int index
                            width: 424
                            height: 32
                            color: index === win.browseCursor ? "#22222c" : "#0f0f18"
                            border.color: index === win.browseCursor ? "#6b6d76" : "#424247"
                            Text {
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.leftMargin: 8
                                anchors.rightMargin: 8
                                anchors.verticalCenter: parent.verticalCenter
                                text: modelData.dir ? modelData.name + "/" : modelData.name
                                color: "#a1a3ad"
                                font.family: win.font.family
                                elide: Text.ElideMiddle
                            }
                            MouseArea {
                                anchors.fill: parent
                                onClicked: {
                                    win.browseCursor = index
                                    backend.browseEnter(index)
                                }
                            }
                        }
                    }
                }
            }
            Row {
                spacing: 8
                TextField {
                    id: remoteFolderField
                    width: 300
                    placeholderText: "New folder"
                    placeholderTextColor: "#7e8089"
                    color: "#a1a3ad"
                    font.family: win.font.family
                    background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                    Keys.onReturnPressed: win.makeRemoteFolder()
                    Keys.onEnterPressed: win.makeRemoteFolder()
                }
                ActionButton { label: "Create folder"; onActivated: win.makeRemoteFolder() }
            }
            TextField {
                id: remoteImageField
                visible: backend.protocol === 2
                width: 424
                placeholderText: "Disk image name"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                Keys.onReturnPressed: backend.browseChoose(text)
                Keys.onEnterPressed: backend.browseChoose(text)
            }
            Text {
                visible: backend.error !== ""
                text: backend.error
                color: "#a17675"
                width: 424
                wrapMode: Text.Wrap
                maximumLineCount: 4
                elide: Text.ElideRight
                font.family: win.font.family
            }
            Row {
                spacing: 8
                ActionButton {
                    label: backend.protocol === 2 ? "Use this file" : "Use this folder"
                    primary: true
                    onActivated: backend.browseChoose(remoteImageField.text)
                }
                ActionButton { label: "Up"; onActivated: backend.browseUp() }
                ActionButton { label: "Cancel"; onActivated: backend.browseCancel() }
            }
        }
    }

    Rectangle {
        visible: win.hostsOpen
        anchors.centerIn: parent
        width: 460
        height: Math.min(560, hostCol.implicitHeight + 36)
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: hostCol
            x: 18
            y: 18
            width: 424
            spacing: 8
            Text { text: "Computers"; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 424; wrapMode: Text.Wrap; text: "Each Tailscale machine has a user and a password. J and K move. Enter opens the highlighted computer. Leave the password empty to use Tailscale SSH or the key you already have. The password is not saved. A typed host below uses that key."; color: "#7e8089"; font.family: win.font.family }
            Flickable {
                width: 424
                height: 220
                contentHeight: hostList.implicitHeight
                clip: true
                Column {
                    id: hostList
                    width: 424
                    spacing: 4
                    Repeater {
                        model: backend.hosts
                        delegate: Rectangle {
                            id: hostRow
                            required property var modelData
                            required property int index
                            width: 424
                            height: modelData.via === "tailscale" ? tailCreds.implicitHeight + 12 : 46
                            color: index === win.hostCursor ? "#22222c" : "#0f0f18"
                            border.color: index === win.hostCursor ? "#6b6d76" : "#424247"
                            border.width: 1

                            function openThisHost() {
                                win.hostCursor = index
                                if (modelData.id === "local") {
                                    win.requestDisconnect()
                                    return
                                }
                                if (modelData.via === "tailscale") {
                                    backend.setHostLogin(modelData.id, peerUser.text, peerPassword.text)
                                    backend.useHost(modelData.id, peerUser.text, peerPassword.text)
                                    return
                                }
                                backend.useHost(modelData.id, hostUserField.text)
                            }

                            function noteHostFocus(focused) {
                                if (focused) {
                                    win.hostCursor = index
                                    win.hostFieldFocus = 1
                                    return
                                }
                                Qt.callLater(function() {
                                    if (!peerUser.activeFocus && !peerPassword.activeFocus)
                                        win.hostFieldFocus = 0
                                })
                            }

                            function fillLogin() {
                                if (!peerUser.activeFocus)
                                    peerUser.text = modelData.user
                                if (!peerPassword.activeFocus)
                                    peerPassword.text = modelData.password
                            }

                            Component.onCompleted: fillLogin()
                            onModelDataChanged: fillLogin()

                            Column {
                                id: tailCreds
                                visible: modelData.via === "tailscale"
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.leftMargin: 8
                                anchors.rightMargin: 8
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: 4
                                Item {
                                    width: parent.width
                                    height: peerName.implicitHeight + peerDetail.implicitHeight + 2
                                    Text { id: peerName; width: parent.width; elide: Text.ElideRight; text: modelData.name; color: "#bcbec8"; font.family: win.font.family }
                                    Text {
                                        id: peerDetail
                                        width: parent.width
                                        anchors.top: peerName.bottom
                                        elide: Text.ElideRight
                                        text: modelData.detail
                                        color: "#7e8089"
                                        font.pixelSize: 11
                                        font.family: win.font.family
                                    }
                                    MouseArea {
                                        anchors.fill: parent
                                        onClicked: hostRow.openThisHost()
                                    }
                                }
                                Row {
                                    width: parent.width
                                    spacing: 8
                                    TextField {
                                        id: peerUser
                                        width: 150
                                        placeholderText: "User"
                                        placeholderTextColor: "#7e8089"
                                        color: "#a1a3ad"
                                        font.family: win.font.family
                                        inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                                        background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                                        onActiveFocusChanged: hostRow.noteHostFocus(activeFocus)
                                        onTextEdited: backend.setHostLogin(modelData.id, text, peerPassword.text)
                                        onAccepted: hostRow.openThisHost()
                                    }
                                    TextField {
                                        id: peerPassword
                                        width: parent.width - 158
                                        echoMode: TextInput.Password
                                        placeholderText: "Password"
                                        placeholderTextColor: "#7e8089"
                                        color: "#a1a3ad"
                                        font.family: win.font.family
                                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                                        background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                                        onActiveFocusChanged: hostRow.noteHostFocus(activeFocus)
                                        onTextEdited: backend.setHostLogin(modelData.id, peerUser.text, text)
                                        onAccepted: hostRow.openThisHost()
                                    }
                                }
                            }
                            Column {
                                visible: modelData.via !== "tailscale"
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.leftMargin: 8
                                anchors.rightMargin: 8
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: 1
                                Text { width: parent.width; elide: Text.ElideRight; text: modelData.name; color: "#bcbec8"; font.family: win.font.family }
                                Text { width: parent.width; elide: Text.ElideRight; text: modelData.detail; color: "#7e8089"; font.pixelSize: 11; font.family: win.font.family }
                            }
                            MouseArea {
                                anchors.fill: parent
                                visible: modelData.via !== "tailscale"
                                onClicked: hostRow.openThisHost()
                            }
                        }
                    }
                }
            }
            TextField {
                id: hostUserField
                width: 424
                placeholderText: "SSH user"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
            }
            TextField {
                id: hostNameField
                width: 424
                placeholderText: "Host or Tailscale name"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
            }
            TextField {
                id: hostPortField
                width: 424
                placeholderText: "Port 22"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                text: "22"
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
            }
            Text {
                visible: backend.connecting
                width: 424
                wrapMode: Text.Wrap
                text: backend.notice
                color: "#a1a3ad"
                font.family: win.font.family
            }
            Text { visible: backend.error !== ""; text: backend.error; color: "#a17675"; width: 424; wrapMode: Text.Wrap; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton {
                    label: "Connect"
                    primary: true
                    onActivated: win.connectTypedHost()
                }
                ActionButton { label: "Disconnect"; visible: backend.remote; onActivated: win.requestDisconnect() }
                ActionButton { label: "Trust key"; visible: backend.canTrustHost; onActivated: backend.trustHost() }
                ActionButton { label: "Close"; onActivated: win.hostsOpen = false }
            }
        }
    }

    Rectangle {
        visible: win.needsOpen
        anchors.centerIn: parent
        width: 480
        height: needCol.implicitHeight + 36
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: needCol
            x: 18
            y: 18
            width: 444
            spacing: 10
            Text { text: "Needed on " + backend.hostTitle; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 444; wrapMode: Text.Wrap; text: backend.needsText; color: "#a1a3ad"; font.family: win.font.family }
            Text {
                visible: backend.error !== ""
                width: 444
                wrapMode: Text.Wrap
                maximumLineCount: 8
                elide: Text.ElideRight
                text: backend.error
                color: "#a17675"
                font.family: win.font.family
            }
            Row {
                spacing: 8
                ActionButton { label: "Install"; primary: true; visible: backend.canInstall; onActivated: { if (backend.installNeeds()) win.needsOpen = false } }
                ActionButton { label: "Not now"; onActivated: win.needsOpen = false }
                ActionButton { label: "Disconnect"; visible: backend.remote; onActivated: win.requestDisconnect() }
            }
        }
    }

    Rectangle {
        visible: win.removeOpen
        anchors.centerIn: parent
        width: 420
        height: removeCol.implicitHeight + 36
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: removeCol
            x: 18
            y: 18
            width: 384
            spacing: 12
            Text { text: backend.removeLabel; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 384; wrapMode: Text.Wrap; text: backend.removeQuestion; color: "#a1a3ad"; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Remove"; key: ""; danger: true; onActivated: win.confirmRemove() }
                ActionButton { label: "Keep"; key: ""; onActivated: win.removeOpen = false }
            }
        }
    }

    Rectangle {
        visible: win.passwordsOpen
        anchors.centerIn: parent
        width: 420
        height: passwordCol.implicitHeight + 36
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: passwordCol
            x: 18
            y: 18
            width: 384
            spacing: 12
            Text { text: "Samba passwords"; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text {
                width: 384
                wrapMode: Text.Wrap
                color: "#7e8089"
                font.family: win.font.family
                text: backend.protocol === 3
                      ? "Creates an access user or key on the named backend. A generated secret is shown once and is not saved here."
                      : backend.protocol === 0
                        ? "This sets the Samba password only. The Linux login password stays as it is."
                        : "Samba passwords are on the Samba page. S3 access keys are on the S3 page."
            }
            Text { width: 384; wrapMode: Text.Wrap; color: "#a1a3ad"; font.family: win.font.family; text: backend.protocol === 3 ? backend.accessLine : backend.userLine }
            TextField {
                id: serviceField
                visible: backend.protocol === 3
                width: 384
                placeholderText: "Backend"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
            }
            TextField {
                id: accountField
                visible: backend.protocol === 0 || backend.protocol === 3
                width: 384
                placeholderText: "Account"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
            }
            TextField {
                id: secretField
                visible: backend.protocol === 0 || backend.protocol === 3
                width: 384
                echoMode: TextInput.Password
                placeholderText: "Password"
                placeholderTextColor: "#7e8089"
                color: "#a1a3ad"
                font.family: win.font.family
                background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
            }
            Text { visible: backend.lastOutput !== ""; width: 384; wrapMode: Text.Wrap; color: "#bcbec8"; font.family: win.font.family; text: backend.lastOutput }
            Text { visible: backend.error !== "" && win.passwordsOpen; text: backend.error; color: "#a17675"; width: 384; wrapMode: Text.Wrap; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Set"; key: ""; primary: true; visible: backend.protocol === 0 || backend.protocol === 3; onActivated: win.applyPassword() }
                ActionButton { label: "Remove"; key: ""; danger: true; visible: backend.protocol === 0 || backend.protocol === 3; onActivated: win.removePassword() }
                ActionButton { label: "Close"; key: ""; onActivated: win.passwordsOpen = false }
            }
        }
    }

    Rectangle {
        visible: win.editorOpen
        anchors.centerIn: parent
        width: 480
        height: Math.min(560, editorCol.implicitHeight + 36)
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: editorCol
            x: 18
            y: 18
            width: 444
            spacing: 10
            Text { text: "Edit " + (backend.detail.name || ""); color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 444; wrapMode: Text.Wrap; text: "The name and path stay as they were created. Save writes this."; color: "#7e8089"; font.family: win.font.family }
            Flickable {
                width: 444
                height: 280
                contentHeight: editorField.implicitHeight
                clip: true
                TextArea {
                    id: editorField
                    width: 444
                    color: "#a1a3ad"
                    font.family: win.font.family
                    wrapMode: TextEdit.Wrap
                    background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                }
            }
            Text { visible: backend.error !== ""; text: backend.error; color: "#a17675"; width: 444; wrapMode: Text.Wrap; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Apply"; key: ""; primary: true; onActivated: win.applyEditorAndClose() }
                ActionButton { label: "Cancel"; key: ""; onActivated: win.editorOpen = false }
            }
        }
    }

    Rectangle {
        visible: win.globalOpen
        anchors.centerIn: parent
        width: 480
        height: Math.min(520, globalCol.implicitHeight + 36)
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: globalCol
            x: 18
            y: 18
            width: 444
            spacing: 10
            Text { text: "Samba global"; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 444; wrapMode: Text.Wrap; text: "Workgroup, server string, log level, and the MacOS preset."; color: "#7e8089"; font.family: win.font.family }
            Flickable {
                width: 444
                height: 220
                contentHeight: globalField.implicitHeight
                clip: true
                TextArea {
                    id: globalField
                    width: 444
                    color: "#a1a3ad"
                    font.family: win.font.family
                    wrapMode: TextEdit.Wrap
                    background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                }
            }
            Text { visible: backend.error !== "" && win.globalOpen; text: backend.error; color: "#a17675"; width: 444; wrapMode: Text.Wrap; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Apply"; key: ""; primary: true; onActivated: win.applyGlobalAndClose() }
                ActionButton { label: "Cancel"; key: ""; onActivated: win.globalOpen = false }
            }
        }
    }

    Rectangle {
        visible: win.importOpen
        anchors.centerIn: parent
        width: 520
        height: Math.min(560, importCol.implicitHeight + 36)
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: importCol
            x: 18
            y: 18
            width: 484
            spacing: 10
            Text { text: "Import / export"; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 484; wrapMode: Text.Wrap; text: "This text is the current service. Import replaces it in the window. Save writes it. A Samba file that still has share sections is backed up as smb.conf.bak."; color: "#7e8089"; font.family: win.font.family }
            Flickable {
                width: 484
                height: 240
                contentHeight: importField.implicitHeight
                clip: true
                TextArea {
                    id: importField
                    width: 484
                    color: "#a1a3ad"
                    font.family: win.font.family
                    wrapMode: TextEdit.Wrap
                    background: Rectangle { color: "#0f0f18"; border.color: "#424247" }
                }
            }
            Text { visible: backend.error !== "" && win.importOpen; text: backend.error; color: "#a17675"; width: 484; wrapMode: Text.Wrap; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Import"; key: ""; primary: true; onActivated: win.importAndClose() }
                ActionButton { label: "Copy"; key: ""; onActivated: win.copyImport() }
                ActionButton { label: "Close"; key: ""; onActivated: win.importOpen = false }
            }
        }
    }

    Rectangle {
        visible: win.quitOpen
        anchors.centerIn: parent
        width: 420
        height: quitCol.implicitHeight + 36
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: quitCol
            x: 18
            y: 18
            width: 384
            spacing: 12
            Text { text: "Save changes?"; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 384; wrapMode: Text.Wrap; text: "This window has changes that are not written yet."; color: "#a1a3ad"; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Save and quit"; key: ""; primary: true; onActivated: win.saveAndQuit() }
                ActionButton { label: "Quit"; key: ""; danger: true; onActivated: Qt.quit() }
                ActionButton { label: "Keep editing"; key: ""; onActivated: win.quitOpen = false }
            }
        }
    }

    Rectangle {
        visible: win.leaveOpen
        anchors.centerIn: parent
        width: 420
        height: leaveCol.implicitHeight + 36
        color: "#16161e"
        border.color: "#424247"
        Column {
            id: leaveCol
            x: 18
            y: 18
            width: 384
            spacing: 12
            Text { text: "Leave " + backend.hostTitle + "?"; color: "#bcbec8"; font.pixelSize: 16; font.bold: true; font.family: win.font.family }
            Text { width: 384; wrapMode: Text.Wrap; text: "Changes in this window are not written."; color: "#a1a3ad"; font.family: win.font.family }
            Text { visible: backend.error !== ""; text: backend.error; color: "#a17675"; width: 384; wrapMode: Text.Wrap; font.family: win.font.family }
            Row {
                spacing: 8
                ActionButton { label: "Save and leave"; key: "Enter"; primary: true; onActivated: win.saveAndLeave() }
                ActionButton { label: "Leave"; key: "X"; danger: true; onActivated: win.finishDisconnect() }
                ActionButton { label: "Keep editing"; key: "Esc"; onActivated: win.leaveOpen = false }
            }
        }
    }

    Connections {
        target: backend
        function onProtocolChanged() { filterField.text = "" }
    }
}
