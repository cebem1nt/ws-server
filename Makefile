CXX = g++
CXXFLAGS = -Wall

SRCS = server/server.c server/crypt.c server/frames.c server/structs.cpp
TARGET = dist/server

all: tsc_build $(TARGET)  

$(TARGET): $(SRCS)
	mkdir -p dist
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET)

tsc_build:
	tsc

run: $(TARGET) tsc_build
	./$(TARGET)

clean:
	rm -rf dist/
