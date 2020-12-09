let xhr;
let mes;
if (window.XMLHttpRequest) { // code for IE7+, Firefox, Chrome, Opera, Safari
    xhr = new XMLHttpRequest();
} else { // code for IE6, IE5
    xhr = new ActiveXObject("Microsoft.XMLHTTP");
}
xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
        if ((xhr.status >= 200 && xhr.status < 300) || xhr.status == 304) {
            mes = JSON.parse(xhr.responseText);
            console.log(mes);
            console.log(mes.Diff);
            const app = new Vue({
                el: '#app',
                data: {
                    file: mes.Diff,
                    type: mes.Info,
                    key: mes.Magic,
                    name: mes.Name
                }
            })
        }
    }
};
xhr.open("get", "./demo.json", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(null);