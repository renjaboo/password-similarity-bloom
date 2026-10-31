CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
# MD5() is flagged as deprecated in OpenSSL 3.x; we only use it for bit-index generation,
# not for security, so the warning is silenced here.
CXXFLAGS += -Wno-deprecated-declarations
LDFLAGS  := -lssl -lcrypto

TARGET := bin/password_checker
SRC    := src/main.cpp

.PHONY: all run test clean

all: $(TARGET)

$(TARGET): $(SRC)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

run: all
	./$(TARGET)

test: all
	bash tests/run_tests.sh $(TARGET)

clean:
	rm -rf bin
