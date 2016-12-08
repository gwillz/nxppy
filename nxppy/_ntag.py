from nxppy._mifare import Mifare, SelectError, WriteError, ReadError
"""
TODO DOCS
"""

class Ntag(object):
    """TODO DOCS"""
    BLOCK_SIZE = 4
    INIT_BLOCK = 4
    
    def __init__(self, end_char="\0"):
        self._mifare = Mifare()
        self._end = end_char
        self._blocks = 0
        self._bytes = 0
    
    
    def select(self):
        """TODO DOCS"""
        
        uid = self._mifare.select() # this throws on error
        
        try:
            ver = self._mifare.get_version()
            
            if ver['tag_type'] != 0x04: # NTAG type
                raise SelectError("not a valid NTAG21x tag")
            
            # determine size limits
            # TODO it thinks ntag216 is exactly 512?
            tag_s = ver['tag_size'] >> 1 # most significant bits?
            
            if ver['tag_size'] >> 3 == 1: # least significant bit?
                size = (2**tag_s, 2**(tag_s+1))
            else:
                size = (2**tag_s, 2**tag_s)
            
            # if size[0] < self.MIN_SIZE:
                # raise SelectError("tag too small {} < {}".format(size[0], self.MIN_SIZE))
            
            # this means it has a CC page
            cc = self._mifare.read_block(3)
            size_bytes = ord(cc[2]) * 8
            
            self._blocks = size_bytes / self.BLOCK_SIZE
            self._bytes = (size_bytes, size[0], size[1])
        
        except ReadError as e:
            raise SelectError("not a valid NTAG21x tag")
        
        return uid
    
    
    def _check_block(self, block):
        """TODO DOCS"""
        
        if not self._blocks:
            raise WriteError("No tag selected")
        
        end_block = self.INIT_BLOCK + self._blocks
        if block < self.INIT_BLOCK or block >= end_block:
            raise WriteError("invalid block number. {} < block < {}".format(self.INIT_BLOCK-1, end_block))
    
    
    def size(self):
        if not self._blocks:
            raise WriteError("No tag selected")
        return self._blocks * self.BLOCK_SIZE
    
    
    def read(self, block):
        """TODO DOCS"""
        
        self._check_block(block)
        
        read = ""
        for i in range(block, self._blocks):
            d = self._mifare.read_block(i)
            read += d
            if len(d) == 0 or self._end in d:
                break
        
        return read.replace("\0", "")
    
    
    def write(self, block, payload):
        """TODO DOCS"""
        
        self._check_block(block)
        
        if payload[-1] != self._end:
            payload += self._end
        
        #size_blocks = -(-len(payload) // self.BLOCK_SIZE)
        
        for b, i in enumerate(xrange(0, len(payload), self.BLOCK_SIZE), start=block):
            if b >= self._blocks:
                raise OverflowError("Payload too big {} < {}".format(self._blocks, b))
            
            data = payload[i:i+self.BLOCK_SIZE]
            if len(data) < 4:
                data = "{:\0<4}".format(data)
            
            self._mifare.write_block(b, data)
    
    
    def clear(self, start_block, end_block):
        """TODO DOCS"""
        
        self._check_block(start_block)
        
        for i in range(start_block, end_block):
            self._mifare.clear_block(i)
    
    
    def clear_all(self):
        """TODO DOCS"""
        self.clear(self.INIT_BLOCK, self._blocks)