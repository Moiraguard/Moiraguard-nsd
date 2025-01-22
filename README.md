# MOIRAGUARD-NSD 
## A Network security tool detect and alert users to potential network scanning activities in real-time.

### Screenshots

#### Main Interface:
![Local image](Moiraguard-nsd_main_interface.jpeg)


# Getting Started with MoiraGuard-NSD Using Docker

Follow these steps to run MoiraGuard from Docker Hub:

---

## 1. Prerequisites

Ensure that Docker is installed on your system. If not, you can follow the [Docker installation guide](https://docs.docker.com/get-docker/) for your operating system.

---

## 2. Pull the MoiraGuard Image from Docker Hub

To pull the pre-built MoiraGuard image from Docker Hub, run the following command:

```bash
sudo docker pull moiraguard/moiraguard-nsd:v1
```
---
## 3. Run the Docker Container (Foreground Mode)

To run the container interactively in the foreground, execute:

```bash
sudo docker run -it --rm \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  --network=host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  moiraguard/moiraguard-nsd:v1

```
---
## 4. Run the Docker Container (Background Mode)

To run the container in the background (detached mode), add the -d flag:
```bash
sudo docker run -d \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  --network=host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  --name moiraguard-container \
  moiraguard/moiraguard-nsd:v1
```
---
Explanation of Flags:

    -d: Runs the container in detached mode.

    --name moiraguard-container: Assigns a specific name to the container for easy reference.

You can check if the container is running using:

```bash
sudo docker ps
```

To stop the container later, run:
```bash
sudo docker stop moiraguard-container
```
---
## 5. Set the DISPLAY Variable Properly (if faced issues related to Display)

If you encounter the issue where the error message states that the Qt platform plugin "xcb" could not connect to the X11 display, it is likely because the Docker container is trying to access your graphical environment but fails due to missing permissions or improper configuration.

If the graphical interface does not work immediately, try setting the DISPLAY variable as follows:

```bash
export DISPLAY=:0
```

Also Allow Docker to Access the X11 Display 
In some systems, you need to explicitly allow Docker containers to access the X11 display. Run the following command on your host machine:

```bash
xhost +local:docker
```
---
## 6. Monitor Alerts

Once the container is running, Chose interface you want to monitor then MoiraGuard-NSD will  begin monitoring network scanning activities. Alerts will appear via desktop notifications and in the system tray.

---
## 7. Export Logs and Analyze Data

MoiraGuard-NSD logs scanning activities, which can be exported in JSON format for further analysis or integration with other security tools.

---
## 8. Stop the MOIRAGUAR-NSD Container


    If you are running in the foreground mode, press Ctrl + C in the terminal to stop the container.

    If running in background mode, stop the container with:

```bash
sudo docker stop moiraguard-container
```
---




