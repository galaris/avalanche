all clean :
	@for dir in $(DIRS); do \
	    $(MAKE) -C $$dir $@ || fail=1; \
	done; \
	test "x$$fail" = x
            
.PHONY : all clean

