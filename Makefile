.DEFAULT_GOAL := all
SHELL := /bin/bash

BUILD_DIR   := $(CURDIR)/builds
SWAY_DIR    := $(CURDIR)/swaylock-mod
WDU_DIR     := $(CURDIR)/wdu
INSTALL_DIR := $(HOME)/.wraith/bin

SWAY_BIN := swaylock
WDU_BIN  := wdu

GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
BLUE   := \033[0;34m
BOLD   := \033[1m
RESET  := \033[0m

# ---------------------------------------------------------
# 🔍 Dependency Checks
# ---------------------------------------------------------
define require
	@command -v $(1) >/dev/null 2>&1 || { \
		echo -e "$(RED)✖ Missing dependency: $(1)$(RESET)"; \
		echo -e "  → Please install $(1) and retry."; \
		exit 1; \
	}
endef

# ---------------------------------------------------------
# Help
# ---------------------------------------------------------
help:
	@echo -e "$(BLUE)Usage:$(RESET)"
	@echo "  make <target>\n"
	@echo -e "$(BLUE)Available targets:$(RESET)"
	@echo "  help            Show this help menu"
	@echo "  all             Build all components"
	@echo "  swaylock        Build swaylock"
	@echo "  wdu             Build wdu"
	@echo "  install         Build and install binaries"
	@echo "  clean           Remove all build artifacts\n"

# ---------------------------------------------------------
# Targets
# ---------------------------------------------------------
all: swaylock wdu
	@echo -e "\n$(GREEN)All builds completed$(RESET)"
	@echo -e "$(BOLD)Artifacts in $(BUILD_DIR)$(RESET)"

prepare:
	@mkdir -p $(BUILD_DIR)

swaylock: prepare
	@echo -e "\n$(BOLD)Building Swaylock$(RESET)"
	$(call require,meson)
	$(call require,ninja)

	@if [ ! -d "$(SWAY_DIR)/build" ]; then \
		echo -e "$(YELLOW)Configuring Meson$(RESET)"; \
		cd $(SWAY_DIR) && meson setup build; \
	fi

	@cd $(SWAY_DIR) && meson compile -C build
	@cp $(SWAY_DIR)/build/$(SWAY_BIN) $(BUILD_DIR)/$(SWAY_BIN)
	@echo -e "$(GREEN)Swaylock built successfully$(RESET)"

wdu: prepare
	@echo -e "\n$(BOLD)Building WDU$(RESET)"
	$(call require,go)

	@cd $(WDU_DIR) && go build -o $(BUILD_DIR)/$(WDU_BIN)
	@echo -e "$(GREEN)WDU built successfully$(RESET)"

install: all
	@echo -e "\n$(BOLD)Installing binaries$(RESET)"
	@mkdir -p $(INSTALL_DIR)
	@cp $(BUILD_DIR)/$(SWAY_BIN) $(INSTALL_DIR)/
	@cp $(BUILD_DIR)/$(WDU_BIN) $(INSTALL_DIR)/
	@echo -e "$(GREEN)Installed to $(INSTALL_DIR)$(RESET)"

clean:
	@echo -e "\n$(YELLOW)Cleaning build artifacts$(RESET)"
	@rm -rf $(BUILD_DIR)
	@rm -rf $(SWAY_DIR)/build
	@echo -e "$(GREEN)Clean complete$(RESET)\n"
