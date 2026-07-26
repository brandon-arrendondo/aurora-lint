/*
 * Rule: MEM12-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

static struct task_struct *copy_process(unsigned long clone_flags,
                    unsigned long stack_start,
                    struct pt_regs *regs,
                    unsigned long stack_size,
                    int __user *child_tidptr,
                    struct pid *pid,
                    int trace)
{
  int retval;
  struct task_struct *p;
  int cgroup_callbacks_done = 0;

  if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
    return ERR_PTR(-EINVAL);

  /* ... */

  retval = security_task_create(clone_flags);
  if (retval)
    goto fork_out;

  retval = -ENOMEM;
  p = dup_task_struct(current);
  if (!p)
    goto fork_out;

  /* ... */

  /* Copy all the process information */
  if ((retval = copy_semundo(clone_flags, p)))
    goto bad_fork_cleanup_audit;
  if ((retval = copy_files(clone_flags, p)))
    goto bad_fork_cleanup_semundo;
  if ((retval = copy_fs(clone_flags, p)))
    goto bad_fork_cleanup_files;
  if ((retval = copy_sighand(clone_flags, p)))
    goto bad_fork_cleanup_fs;
  if ((retval = copy_signal(clone_flags, p)))
    goto bad_fork_cleanup_sighand;
  if ((retval = copy_mm(clone_flags, p)))
    goto bad_fork_cleanup_signal;
  if ((retval = copy_namespaces(clone_flags, p)))
    goto bad_fork_cleanup_mm;
  if ((retval = copy_io(clone_flags, p)))
    goto bad_fork_cleanup_namespaces;
  retval = copy_thread(0, clone_flags, stack_start, stack_size, p, regs);
  if (retval)
    goto bad_fork_cleanup_io;

  /* ... */

  return p;

  /* ... Cleanup code starts here ... */

bad_fork_cleanup_io:
  put_io_context(p->io_context);
bad_fork_cleanup_namespaces:
  exit_task_namespaces(p);
bad_fork_cleanup_mm:
  if (p->mm)
    mmput(p->mm);
bad_fork_cleanup_signal:
  cleanup_signal(p);
bad_fork_cleanup_sighand:
  __cleanup_sighand(p->sighand);
bad_fork_cleanup_fs:
  exit_fs(p); /* Blocking */
bad_fork_cleanup_files:
  exit_files(p); /* Blocking */
bad_fork_cleanup_semundo:
  exit_sem(p);
bad_fork_cleanup_audit:
  audit_free(p);

  /* ... More cleanup code ... */

fork_out:
  return ERR_PTR(retval);
}