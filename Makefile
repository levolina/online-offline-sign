#Compiler and Linker
CC          := g++

#The Target Binary Program
TARGET      := program

#Dependencies 
BOTANDIR    := ./deps/botan

#The Directories, Source, Includes, Objects, Binary
SRCDIR      := src
INCDIR      := $(BOTANDIR)/build/include
OBJDIR      := obj
LIBDIR      := $(BOTANDIR)
TARGETDIR   := bin
SRCEXT      := cpp
DEPEXT      := d
OBJEXT      := o

#Flags, Libraries and Includes
CFLAGS      :=
LIB         := -lstdc++ -lbotan-3
INC         := -I$(INCDIR) -I/usr/local/include
INCDEP      := -I$(INCDIR)
LDFLAGS     := -L$(LIBDIR)

#---------------------------------------------------------------------------------
#DO NOT EDIT BELOW THIS LINE
#---------------------------------------------------------------------------------
SOURCES     := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS     := $(patsubst $(SRCDIR)/%,$(OBJDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

#Defauilt Make
all: directories $(TARGET)

#Remake
remake: cleaner all

#Make the Directories
directories:
	@mkdir -p $(TARGETDIR)
	@mkdir -p $(OBJDIR)

#Clean only Objecst
clean:
	@$(RM) -rf $(OBJDIR)

#Full Clean, Objects and Binaries
cleaner: clean
	@$(RM) -rf $(TARGETDIR)

#Pull in dependency info for *existing* .o files
-include $(OBJECTS:.$(OBJEXT)=.$(DEPEXT))

#Link
$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGETDIR)/$(TARGET) $^ $(LDFLAGS) $(LIB) 

#Compile
$(OBJDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<
	@$(CC) $(CFLAGS) $(INCDEP) -MM $(SRCDIR)/$*.$(SRCEXT) > $(OBJDIR)/$*.$(DEPEXT)
	@cp -f $(OBJDIR)/$*.$(DEPEXT) $(OBJDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(OBJDIR)/$*.$(OBJEXT):|' < $(OBJDIR)/$*.$(DEPEXT).tmp > $(OBJDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(OBJDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(OBJDIR)/$*.$(DEPEXT)
	@rm -f $(OBJDIR)/$*.$(DEPEXT).tmp

#Non-File Targets
.PHONY: all remake clean cleaner