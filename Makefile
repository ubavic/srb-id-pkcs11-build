CXX = g++
CXXFLAGS += -I/usr/local/include -I/usr/include/PCSC -fPIC -Wall -std=c++20
LDFLAGS = -shared

SRC = decryption.cpp \
	digest.cpp \
	dualPurpose.cpp \
	dualPurpose.cpp \
	encryption.cpp \
	general.cpp \
	keyManagement.cpp \
	objectManagement.cpp \
	parallel.cpp \
	random.cpp \
	session.cpp \
	sign.cpp \
	slotAndToken.cpp \
	state.cpp \
	verify.cpp
BUILD_DIR = build
OBJ = $(patsubst %.cpp, $(BUILD_DIR)/%.o, $(SRC))
TARGET = srb-id-pkcs11-x64.so

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ -lpcsclite

$(BUILD_DIR)/%.o: ./src/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<
	
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
