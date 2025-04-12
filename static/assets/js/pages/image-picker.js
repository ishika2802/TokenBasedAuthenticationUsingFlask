'use strict';
$(document).ready(function () {
    let isTriggered = false;  // Flag to prevent multiple triggers

    $('.image-picker').on('click', function (event) {
        if (!isTriggered) {
            isTriggered = true;
            $('#fileInput').click();
            setTimeout(() => { isTriggered = false; }, 500); // Reset flag after a short delay
        }
    });

    $('#fileInput').on('change', function (event) {
        let file = event.target.files[0];

        if (file) {
            let reader = new FileReader();
            reader.onload = function (e) {
                $('#preview').attr('src', e.target.result);
            };
            reader.readAsDataURL(file);
        }
    });
});
