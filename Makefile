#Compiler and Linker
CC          := g++

#The Target Library
TARGET      := liboosign.so

#Dependencies 
BOTANDIR    := ./deps/botan

#The Directories, Source, Includes, Objects, Binary
SRCDIR      := src
INCDIR      := $(BOTANDIR)/build/include
OBJDIR      := obj
LIBDIR      := $(BOTANDIR)
HDRDIR      := include
TARGETDIR   := bin
SRCEXT      := cpp
HDREXT      := hpp
DEPEXT      := d
OBJEXT      := o

#Flags, Libraries and Includes
CFLAGS      := -Wall -Wextra -fPIC -O2 -g
LIB         := -lstdc++ -lbotan-3
INC         := -I$(INCDIR)
LDFLAGS     := -L$(LIBDIR)
#SHARE_LIBS  := -Wl,-R$(LIBDIR) -Wl,-R../bin

#---------------------------------------------------------------------------------
#DO NOT EDIT BELOW THIS LINE
#---------------------------------------------------------------------------------
SOURCES     := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS     := $(patsubst $(SRCDIR)/%,$(OBJDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

all: directories $(TARGET) test

#Remake
remake: clean all

#Make tests
test: $(HDRDIR)
	cd test && make

#Make the Directories
directories:
	@mkdir -p $(TARGETDIR)
	@mkdir -p $(OBJDIR)

#Full Clean, Objects and Binaries
clean: 
	@$(RM) -rf $(TARGETDIR)
	@$(RM) -rf $(OBJDIR)
	@$(RM) -rf $(HDRDIR)
	@cd test && make clean

#Pull in dependency info for *existing* .o files
-include $(OBJECTS:.$(OBJEXT)=.$(DEPEXT))

#Library Link
$(TARGET): $(OBJECTS)
	$(CC) -shared -o $(TARGETDIR)/$(TARGET) $^ $(LDFLAGS) $(LIB) $(SHARE_LIBS)

#Compile
$(OBJDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<
	@$(CC) $(CFLAGS) $(INC) -MM $(SRCDIR)/$*.$(SRCEXT) > $(OBJDIR)/$*.$(DEPEXT)
	@cp -f $(OBJDIR)/$*.$(DEPEXT) $(OBJDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(OBJDIR)/$*.$(OBJEXT):|' < $(OBJDIR)/$*.$(DEPEXT).tmp > $(OBJDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(OBJDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(OBJDIR)/$*.$(DEPEXT)
	@rm -f $(OBJDIR)/$*.$(DEPEXT).tmp

$(HDRDIR):
	@mkdir -p $(HDRDIR)
	@cp $(SRCDIR)/*.$(HDREXT) $(HDRDIR)

#Non-File Targets
.PHONY: all remake clean