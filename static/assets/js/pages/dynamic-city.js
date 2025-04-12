'use strict';

document.addEventListener("DOMContentLoaded", function () {
    let stateDropdown = document.getElementById("state");
    let cityDropdown = document.getElementById("city");
    let savedCity = cityDropdown.dataset.savedCity; // Retrieve saved city from dataset

    stateDropdown.addEventListener("change", function () {
        let selectedState = this.value;

        // Clear previous options
        cityDropdown.innerHTML = '<option value="">Select City</option>';

        if (selectedState) {
            fetch(`/get_cities/${selectedState}`)
                .then(response => response.json())
                .then(data => {
                    data.cities.forEach(city => {
                        let option = document.createElement("option");
                        option.value = city;
                        option.textContent = city;

                        // Check if the city matches the saved one
                        if (city === savedCity) {
                            option.selected = true;
                        }

                        cityDropdown.appendChild(option);
                    });
                })
                .catch(error => console.error("Error fetching cities:", error));
        }
    });
});
