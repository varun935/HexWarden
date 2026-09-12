#include <SPI.h>
#include <TFT_eSPI.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <math.h>

#define BL_PIN  32

TFT_eSPI tft = TFT_eSPI(); 

const char* ssid = "Chakkde";
const char* password = "fatte12345678";
const char* beaconUrl = "http://google.com";

unsigned long lastBeaconTime = 0;
const unsigned long beaconInterval = 5000;

int currentY = 60; // Starting Y for log (adjusted for new layout)

// Radar Variables
float radarAngle = 0.0;
float lastRadarAngle = 0.0;
const int radarCx = 256;
const int radarCy = 115;
const int radarR = 50;
int blipX = 0, blipY = 0, blipTimer = 0;

void drawHeader(String statusStr, uint16_t color) {
  tft.fillRect(0, 0, 320, 50, TFT_BLACK); 
  tft.drawRect(0, 0, 320, 50, TFT_GREEN);
  tft.drawRect(2, 2, 316, 46, TFT_DARKGREEN);
  
  tft.setTextSize(2);
  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.setCursor(10, 8);
  tft.print("C2: "); tft.print(beaconUrl);
  
  tft.setCursor(10, 28);
  tft.print("STS:"); 
  tft.setTextColor(color, TFT_BLACK);
  tft.print(statusStr);
}

void printLog(String msg, uint16_t color) {
  tft.fillRect(0, currentY, 190, 10, TFT_BLACK); // Clear left panel line
  tft.setCursor(2, currentY);
  tft.setTextSize(1);
  tft.setTextColor(color, TFT_BLACK);
  tft.print(">" + msg);
  
  currentY += 10;
  if(currentY > 230) currentY = 60;
}

void printRandomHex() {
  tft.fillRect(0, currentY, 190, 10, TFT_BLACK);
  tft.setCursor(2, currentY);
  tft.setTextColor(0x03E0, TFT_BLACK); 
  tft.setTextSize(1);
  
  String hexLine = "0x" + String(random(0x1000, 0xFFFF), HEX) + " ";
  for(int i = 0; i < 5; i++) {
    String b = String(random(0x00, 0xFF), HEX);
    if(b.length() < 2) b = "0" + b;
    hexLine += b + " ";
  }
  if (random(10) > 8) {
    hexLine += (char)random(33, 126);
  }
  hexLine.toUpperCase();
  tft.print(hexLine);
  
  currentY += 10;
  if(currentY > 230) currentY = 60;
}

void drawRadar() {
  // Erase old sweep line
  int lastX = radarCx + radarR * cos(lastRadarAngle);
  int lastY = radarCy + radarR * sin(lastRadarAngle);
  tft.drawLine(radarCx, radarCy, lastX, lastY, TFT_BLACK);

  // Redraw static radar grid
  tft.drawCircle(radarCx, radarCy, radarR, 0x03E0);
  tft.drawCircle(radarCx, radarCy, radarR/2, 0x03E0);
  tft.drawLine(radarCx - radarR, radarCy, radarCx + radarR, radarCy, 0x03E0);
  tft.drawLine(radarCx, radarCy - radarR, radarCx, radarCy + radarR, 0x03E0);
  
  // Random "blip" generation
  if(random(100) < 3 && blipTimer == 0) {
     float r = random(10, radarR-5);
     float a = random(0, 628) / 100.0;
     blipX = radarCx + r * cos(a);
     blipY = radarCy + r * sin(a);
     blipTimer = 20; 
  }
  
  if(blipTimer > 0) {
     tft.fillCircle(blipX, blipY, 2, TFT_RED);
     blipTimer--;
     if(blipTimer == 0) tft.fillCircle(blipX, blipY, 2, TFT_BLACK);
  }

  // Draw new sweep line
  radarAngle += 0.1;
  if(radarAngle > 2 * PI) radarAngle -= 2 * PI;
  
  int newX = radarCx + radarR * cos(radarAngle);
  int newY = radarCy + radarR * sin(radarAngle);
  tft.drawLine(radarCx, radarCy, newX, newY, TFT_GREEN);
  
  lastRadarAngle = radarAngle;
}

void drawBars() {
  int barBoxX = 200;
  int barBoxY = 185;
  int barW = 14;
  int maxBarH = 45;
  
  for(int i = 0; i < 7; i++) {
     tft.fillRect(barBoxX + (i*16), barBoxY, barW, maxBarH, TFT_BLACK); // erase
     int h = random(2, maxBarH);
     
     uint16_t bColor = 0x03E0; // TFT_DARKGREEN
     if(h > 35) bColor = TFT_RED;
     else if(h > 20) bColor = TFT_GREEN;
     
     tft.fillRect(barBoxX + (i*16), barBoxY + (maxBarH - h), barW, h, bColor);
  }
}

void setup() {
  Serial.begin(115200);
  tft.init();
  tft.setRotation(1); 
  tft.fillScreen(TFT_BLACK);

  ledcAttach(BL_PIN, 25000, 8); 
  ledcWrite(BL_PIN, 255); 

  // --- Cool Geometric Boot Sequence ---
  for(int i=0; i<160; i+=8) {
    tft.drawRect(160 - i, 120 - (i*240/320), i*2, i*2*240/320, TFT_DARKGREEN);
    delay(30);
  }
  tft.fillScreen(TFT_BLACK);
  
  tft.setTextSize(2);
  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  tft.setCursor(10, 100);
  tft.print("UPLINK SYNC...");
  
  WiFi.begin(ssid, password);
  int loadingW = 0;
  while (WiFi.status() != WL_CONNECTED) {
    tft.drawRect(10, 130, 300, 20, TFT_DARKGREEN);
    tft.fillRect(12, 132, loadingW, 16, TFT_GREEN);
    loadingW += 10;
    if(loadingW > 296) { loadingW = 0; tft.fillRect(12, 132, 296, 16, TFT_BLACK); }
    delay(300);
  }
  
  tft.fillScreen(TFT_BLACK);
  
  // Draw layout divider
  tft.drawLine(192, 50, 192, 240, TFT_DARKGREEN);
  drawHeader("AWAITING C2...", TFT_YELLOW);
}

void loop() {
  printRandomHex();
  drawRadar();
  
  static int frameCounter = 0;
  if(frameCounter++ % 3 == 0) {
    drawBars(); // Update bars slightly slower than hex dump
  }
  
  if ((millis() - lastBeaconTime) > beaconInterval) {
    printLog("INIT C2 HANDSHAKE", TFT_YELLOW);
    
    if (WiFi.status() == WL_CONNECTED) {
      HTTPClient http;
      http.begin(beaconUrl);
      int httpResponseCode = http.GET();
      
      if (httpResponseCode > 0) {
        drawHeader("HTTP " + String(httpResponseCode), TFT_GREEN);
        printLog("PAYLOAD SECURED", TFT_GREEN);
      } else {
        drawHeader("ERR " + String(httpResponseCode), TFT_RED);
        printLog("CONNECT FAILED", TFT_RED);
      }
      http.end();
    } else {
      drawHeader("NO UPLINK", TFT_RED);
      printLog("WIFI FATAL", TFT_RED);
    }
    
    lastBeaconTime = millis();
    delay(500); // Visual freeze effect during transmission
  }
  
  delay(20); 
}
