function capture_Pcap(ip, mac) {
    var modal = document.getElementById("pcapModal");
    var ipField = document.getElementById("capture_ip");
    var macField = document.getElementById("capture_mac");

    modal.style.display = "block";
    ipField.value = ip;
    macField.value = mac;
    
}

function editUser(ip, mac) {
    var modal = document.getElementById("editModal");
    var ipField = document.getElementById("edit_ip");
    var macField = document.getElementById("edit_mac");

    modal.style.display = "block";
    ipField.value = ip;
    macField.value = mac;
}

var pcapModal = document.getElementById("pcapModal");
var editModal = document.getElementById("editModal");

window.onclick = function(event) {
    if (event.target == pcapModal) {
        pcapModal.style.display = "none";
    }
    if (event.target == editModal) {
        editModal.style.display = "none";
    }
}

var closeButtons = document.getElementsByClassName("close");
for (var i = 0; i < closeButtons.length; i++) {
    closeButtons[i].onclick = function() {
        pcapModal.style.display = "none";
        editModal.style.display = "none";
    }
}
function closeModal(modalId) {
    var modal = document.getElementById(modalId);
    modal.style.display = "none";
}
