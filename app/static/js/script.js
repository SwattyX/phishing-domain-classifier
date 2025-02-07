document.addEventListener('DOMContentLoaded', function () {
    const urlForm = document.getElementById('urlForm');
    const urlInput = document.getElementById('urlInput');
    const resultDiv = document.getElementById('result');
    const resultAlert = document.getElementById('resultAlert');

    urlForm.addEventListener('submit', async function (event) {
        event.preventDefault(); // Prevent the form from submitting the traditional way

        const urlValue = urlInput.value.trim();

        // Show loading state
        resultDiv.style.display = 'block';
        resultAlert.className = 'alert alert-info';
        resultAlert.textContent = 'Processing...';

        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: urlValue })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Network response was not ok');
            }

            const data = await response.json();
            if (data.success) {
                if (data.prediction === 0) {
                    resultAlert.className = 'alert alert-danger';
                    resultAlert.innerHTML = `<strong style="font-size: 24px; color: red;">Phishing Detected!</strong>
                    <br><span style="font-size: 16px;">Probability: ${(data.probability * 100).toFixed(2)}%</span>
                    <br><span style="font-size: 16px; text-align: left;">Features:</span>
                    <pre style="font-size: 16px; text-align: left;">${data.features}</pre>`;
                } else {
                    resultAlert.className = 'alert alert-success';
                    resultAlert.innerHTML = `<strong style="font-size: 24px; color: #ffffff;">Safe URL!</strong>
                    <br><span style="font-size: 16px;">Probability: ${(data.probability * 100).toFixed(2)}%</span>
                    <br><span style="font-size: 16px; text-align: left;">Features:</span>
                    <pre style="font-size: 16px; text-align: left;">${data.features}</pre>`;
                }
                // if (data.prediction === 0) {
                //     resultAlert.className = 'alert alert-danger';
                //     resultAlert.innerHTML = `<strong style="font-size: 24px; color: red;">Phishing Detected!</strong>
                //     <br><span style="font-size: 16px;">Probability: ${(data.probability * 100).toFixed(2)}%</span>`;
                // } else {
                //     resultAlert.className = 'alert alert-success';
                //     resultAlert.innerHTML = `<strong style="font-size: 24px; color: #ffffff;">Safe URL!</strong>
                //     <br><span style="font-size: 16px;">Probability: ${(data.probability * 100).toFixed(2)}%</span>`;
                // }
            } else {
                throw new Error(data.message || 'An error occurred during prediction.');
            }

        } catch (error) {
            resultAlert.className = 'alert alert-warning';
            resultAlert.textContent = `Error: ${error.message}`;
        }
    });
});
