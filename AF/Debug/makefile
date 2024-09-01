

all: AF

.PHONY: all clean

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include src/deps/sha256/subdir.mk
-include src/deps/hmac-sha256/subdir.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif



# Add inputs and outputs from these tool invocations to the build variables 

# All Target


# Tool invocations

AF: $(AF_OBJS) $(AF_USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: C Linker'
	gcc -o "AF" $(AF_OBJS) $(AF_USER_OBJS) $(AF_LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) $(AF_OBJS) $(C_AF_DEPS) AF
	-@echo ' '



test:
	@echo $(C_SRCS)
	@echo $(OBJS)
	@echo $(C_DEPS)
