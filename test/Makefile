#Compiler and Linker
CC          := g++

#The Target Binary Program
TARGET      := oosign_test

#Dependencies 
BOTANDIR    := ../deps/botan

#The Directories, Source, Includes, Objects, Binary
INCDIR      := $(BOTANDIR)/build/include ../include
OBJDIR      := obj
LIBDIR      := $(BOTANDIR)
TARGETDIR   := bin
SRCEXT      := cpp
DEPEXT      := d
OBJEXT      := o

#Flags, Libraries and Includes
CFLAGS      :=
LIB         := -lstdc++ -lbotan-3 -loosign
INC         := $(addprefix -I,$(INCDIR))
LDFLAGS     := -L$(LIBDIR) -L../bin
SHARE_LIBS  := -Wl,-R$(realpath ../bin) -Wl,-R$(realpath $(LIBDIR))

#---------------------------------------------------------------------------------
#DO NOT EDIT BELOW THIS LINE
#---------------------------------------------------------------------------------
SOURCES     := $(shell find -type f -name "*.$(SRCEXT)")
OBJECTS     := $(patsubst ./%,$(OBJDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

#Defauilt Make
all: directories $(TARGET)

#Remake
remake: clean all

#Make the Directories
directories:
	@mkdir -p $(TARGETDIR)
	@mkdir -p $(OBJDIR)

#Full Clean (Objects and Binaries)
clean:
	@$(RM) -rf $(OBJDIR)
	@$(RM) -rf $(TARGETDIR)

#Pull in dependency info for *existing* .o files
-include $(OBJECTS:.$(OBJEXT)=.$(DEPEXT))

#Link
$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGETDIR)/$(TARGET) $^ $(LDFLAGS) $(LIB) $(SHARE_LIBS)
	@cp $(TARGETDIR)/$(TARGET) ../$(TARGETDIR)/

#Compile
$(OBJDIR)/%.$(OBJEXT): ./%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<
	@$(CC) $(CFLAGS) $(INC) -MM ./$*.$(SRCEXT) > $(OBJDIR)/$*.$(DEPEXT)
	@cp -f $(OBJDIR)/$*.$(DEPEXT) $(OBJDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(OBJDIR)/$*.$(OBJEXT):|' < $(OBJDIR)/$*.$(DEPEXT).tmp > $(OBJDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(OBJDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(OBJDIR)/$*.$(DEPEXT)
	@rm -f $(OBJDIR)/$*.$(DEPEXT).tmp

#Non-File Targets
.PHONY: all remake clean cleaner