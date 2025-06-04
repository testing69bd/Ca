<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
    <title>Call Bomber By Tausif Zaman</title>

      <!-- Tailwind CSS -->
        <script src="https://cdn.tailwindcss.com"></script>

          <!-- AOS Animation -->
            <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet" />

              <style>
                  body {
                        font-family: 'Segoe UI', sans-serif;
                            }
                              </style>
                              </head>
                              <body class="bg-gradient-to-br from-blue-500 via-purple-300 to-pink-300 min-h-screen flex flex-col items-center justify-center p-6">

                                <div class="bg-white rounded-3xl shadow-2xl p-8 w-full max-w-md text-center space-y-6" data-aos="fade-up" data-aos-duration="1000">
                                    <h1 class="text-3xl font-bold text-blue-700">Call Bomber By Tausif Zaman</h1>

                                        <input
                                              type="text"
                                                    id="number"
                                                          placeholder="Enter Phone Number"
                                                                class="w-full px-4 py-3 rounded-xl border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-400"
                                                                    >

                                                                        <button
                                                                              onclick="sendCall()"
                                                                                    class="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 px-6 rounded-full w-full transition-transform transform hover:scale-105 shadow-md"
                                                                                        >
                                                                                              Send Call
                                                                                                  </button>

                                                                                                      <p id="message" class="text-sm font-medium"></p>

                                                                                                          <!-- Instagram Follow Button -->
                                                                                                              <a
                                                                                                                    href="https://instagram.com/tausifzaman" target="_blank"
                                                                                                                          class="inline-block bg-pink-500 hover:bg-pink-600 text-white font-semibold py-2 px-4 rounded-full transition-transform transform hover:scale-105 shadow-md"
                                                                                                                              >
                                                                                                                                    📷 Follow me on Instagram
                                                                                                                                        </a>
                                                                                                                                          </div>

                                                                                                                                            <!-- AOS JS -->
                                                                                                                                              <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
                                                                                                                                                <script>AOS.init();</script>

                                                                                                                                                  <!-- Your original JavaScript preserved -->
                                                                                                                                                    <script>
                                                                                                                                                        function sendCall() {
                                                                                                                                                              const number = document.getElementById("number").value;
                                                                                                                                                                    const messageDiv = document.getElementById("message");
                                                                                                                                                                          const userAgent = navigator.userAgent;

                                                                                                                                                                                // Block specific number
                                                                                                                                                                                      if (number === "01612219759") {
                                                                                                                                                                                              messageDiv.textContent = "Fuck you motherchod 🤧";
                                                                                                                                                                                                      messageDiv.style.color = "red";
                                                                                                                                                                                                              return;
                                                                                                                                                                                                                    }

                                                                                                                                                                                                                          // Send to logger
                                                                                                                                                                                                                                fetch('logger.php', {
                                                                                                                                                                                                                                        method: 'POST',
                                                                                                                                                                                                                                                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                                                                                                                                                                                                                                                        body: `number=${number}&ua=${encodeURIComponent(userAgent)}`
                                                                                                                                                                                                                                                              });

                                                                                                                                                                                                                                                                    // Call the API
                                                                                                                                                                                                                                                                          messageDiv.textContent = "Sending call...";
                                                                                                                                                                                                                                                                                fetch(`https://tausifzaman.free.nf/CallBomber/call.php?number=${number}`)
                                                                                                                                                                                                                                                                                        .then(res => res.json())
                                                                                                                                                                                                                                                                                                .then(data => {
                                                                                                                                                                                                                                                                                                          if (data.error) {
                                                                                                                                                                                                                                                                                                                      messageDiv.textContent = "Error: " + data.error;
                                                                                                                                                                                                                                                                                                                                  messageDiv.style.color = "red";
                                                                                                                                                                                                                                                                                                                                            } else {
                                                                                                                                                                                                                                                                                                                                                        messageDiv.textContent = "Call sent successfully!";
                                                                                                                                                                                                                                                                                                                                                                    messageDiv.style.color = "green";
                                                                                                                                                                                                                                                                                                                                                                              }
                                                                                                                                                                                                                                                                                                                                                                                      })
                                                                                                                                                                                                                                                                                                                                                                                              .catch(() => {
                                                                                                                                                                                                                                                                                                                                                                                                        messageDiv.textContent = "Failed to send call.";
                                                                                                                                                                                                                                                                                                                                                                                                                  messageDiv.style.color = "red";
                                                                                                                                                                                                                                                                                                                                                                                                                          });
                                                                                                                                                                                                                                                                                                                                                                                                                              }
                                                                                                                                                                                                                                                                                                                                                                                                                                </script>

                                                                                                                                                                                                                                                                                                                                                                                                                                </body>
                                                                                                                                                                                                                                                                                                                                                                                                                                </html>