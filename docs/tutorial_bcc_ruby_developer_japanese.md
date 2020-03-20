# RbBCC Ruby Developer Tutorial

* オリジナルの Python バージョンは [BCC本家のリポジトリ](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md) にあります。
* この Ruby 版チュートリアルは、日本語版も含め BCC のライセンスに従います。

---

このチュートリアルは [RbBCC](https://github.com/udzura/rbbcc/) を用いて、Rubyのインタフェースにより bcc のツールを開発するためのチュートリアルです。今回は「可観測性」のパートのみが執筆されています。コードスニペットは [bcc](https://github.com/iovisor/bcc/tree/master/tools) の各所のものを参考にしています: ぜひそれらのライセンスも参照してください。そして、私たちはそれらの Ruby バージョンを [`answers/`](answers/) リポジトリに配置しています。

同時に、 bcc 開発者の [リファレンスガイド](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#bpf-c) も参照し、 C のインターフェースも理解してください。

また、 Python と Lua の bcc インターフェースもあるので、 bcc のオリジナルを参照してください。

## Observability - 可観測性

この可観測性のチュートリアルは 17 のレッスンを含んでいます。

### Lesson 1. Hello World

[answers/01-hello-world.rb](answers/01-hello-world.rb) を実行しましょう。そして、別のターミナルセッションでいくつかコマンドを（例: `"ls"` ）発行しましょう。プロセスを作るたびに「`Hello, World!`」がプリントされるはずです。もし出ない場合、bccのインストールに問題があるでしょう: [BCCの INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md) と [rbbcc getting started](getting_started.md) を見てください。

```bash
## もし bundler の環境で実行しているのなら、 `bundle exec' をつけてください。
# ruby answers/01-hello-world.rb
Found fnc: kprobe__sys_clone
Attach: p___x64_sys_clone
           <...>-17950 [000] .... 244107.900795: 0: Hello, World!
            bash-17950 [000] .... 244110.775263: 0: Hello, World!
            bash-17950 [000] .... 244114.080360: 0: Hello, World!
```

6つの学ぶべきことがあります:

1. ```text: '...'```: これは BPF プログラムをインラインで定義しています。このプログラムは、Cで書きます。

1. ```kprobe__sys_clone()```: これはkprobeによるカーネルの動的トレーシングをするためのショートカット規約です。もし、Cの関数が ``kprobe__`` から開始していたら。残りは計測するカーネルの関数名として扱われます。この場合、 ```sys_clone()``` です。

1. ```void *ctx```: ctx は型があるのですが、今回は使わないので ```void *``` にキャストして捨てています。

1. ```bpf_trace_printk()```: シンプルなカーネルユーティリティで、 ```trace_pipe (/sys/kernel/debug/tracing/trace_pipe)``` に printf() をします。これは単純な例なら問題ないのですが、制限もあります: 引数が3つまで、 `%s` は1つまで、そして `trace_pipe` はマシングローバルであること。なので、並列実行のプログラムではアウトプットがクラッシュするでしょう。より良いインタフェースに `BPF_PERF_OUTPUT()` があり、後述します。

1. ```return 0;```: おまじないです（理由を詳しく知りたければ [bcc#139](https://github.com/iovisor/bcc/issues/139) まで）。

1. ```Table#trace_print```: Ruby側の、trace_pipeを読み込んでアウトプットをプリントするメソッドです。

### Lesson 2. sys_sync()

カーネル関数 `sys_sync()` をトレースするプログラムを書きましょう。実行のたびに "sys_sync() called" をプリントします。トレース中別のターミナルで ```sync``` コマンドを打てばテストできます。さきほどの `hello_world.rb` に必要なものが全て書かれています。

プログラム起動時に "Tracing sys_sync()... Ctrl-C to end." と出力して、改善しましょう。ヒント: これはただの Ruby プログラムで、Ctrl-Cを押したときに投げられる `Interrupt` 例外を rescue できるはずです。

回答例の一つです: [answers/02-sys_sync.rb](answers/02-sys_sync.rb)

Tipsとして、システムコール `sync(2)` を明示的にRubyから呼ぶことも可能です:

```console
# ausyscall sync 
sync               162
# ruby -e 'syscall(162)'
```

### Lesson 3. hello_fields.rb

プログラムは: [answers/03-hello_fields.rb](answers/03-hello_fields.rb). アウトプットのサンプル (コマンドを別のターミナルで打つこと):

```
# bundle exec ruby ./docs/answers/03-hello_fields.rb
TIME(s)            COMM             PID    MESSAGE
24585001.174885999 sshd             1432   Hello, World!
24585001.195710000 sshd             15780  Hello, World!
24585001.991976000 systemd-udevd    484    Hello, World!
24585002.276147000 bash             15787  Hello, World!
```

コードは:

```ruby
require "rbbcc"
include RbBCC

# define BPF program
prog = <<BPF
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
BPF

# load BPF program
b = BCC.new(text: prog)
b.attach_kprobe(event: b.get_syscall_fnname("clone"), fn_name: "hello")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "MESSAGE"])

# format output
begin
  b.trace_fields do |task, pid, cpu, flags, ts, msg|
    print("%-18.9f %-16s %-6d %s" % [ts, task, pid, msg])
  end
rescue Interrupt
  puts
  puts "Done"
rescue => e
  p e
  retry
end
```

これは hello_world.rb に近いもので、 sys_clone() 経由で新しいプロセスをトレースします。しかしいくつか新しい要素があります:

1. ```prog:```: 今回私たちは、Cプログラムを変数に格納し、あとで参照しました。これは、 `String#sub!` などで（例えばコマンドラインの入力をもとに）文字列を操作する際に便利でしょう。

1. ```hello()```: いま、私たちはCの関数を ```kprobe__``` ショートカットなしで宣言しました。後ほど説明します。BPFプログラムで宣言されたどのC関数も、probeの際に実行されることを意図されます。そのため ```pt_reg* ctx``` という変数を最初の引数に指定する必要があります。もしprobeでは実行されることのないヘルパー関数を定義する必要があれば、 ```static inline``` を宣言してコンパイラにインライン化をしてもらう必要があるでしょう。場合により ```_always_inline``` という関数attributeを指定する必要もあるでしょう。

1. ```b.attach_kprobe(event: b.get_syscall_fnname("clone"), fn_name: "hello")```: カーネルのcloneシステムコール関数からkprobeをつくり、先ほど定義した hello() を登録、実行させます。 attach_kprobe() を複数回呼び出して、BPF内の関数を複数のカーネル関数とひもづけることも可能です。

1. ```b.trace_fields do |...|```: trace_pipe を一行読みこんだ内容をブロック引数に格納したループを回します(ブロックなしの場合、 readline() のように読み込んだ返り値のセットを返却します)。trace_print() に近いですがこちらの方がアウトプットの加工には便利です。現実的なツールには `BPF_PERF_OUTPUT()` を使いましょう。

### Lesson 4. sync_timing.rb

思い出しましょう、システム管理者が ```reboot``` をする前に、 ```sync``` を3回、遅いコンソールに打ち込んでいた時代を...。それにより最初の非同期なsyncを確実に完了させていたのでしょうかね？ しかしそれから、誰かが ```sync;sync;sync``` の方がスマートだと思いついて、一行で全てを実行するプラクティスが普及しました。最初の目的がダメになってしまうにうも関わらず！ さらにその後、 sync コマンドは同期的になり、さらに色々な理由でこのプラクティスは馬鹿げたものになりました。やれやれ。

この後のサンプルは、どれだけ素早い間隔で ```do_sync``` が呼び出されたかを計測し、もし1秒よりも感覚が小さかったらそれをプリントするものです。```sync;sync;sync``` などと打った場合は2番目と3番目のsyncを表示してくれることでしょう:

```
# ruby ./answers/04-sync_timing.rb
Tracing for quick sync's... Ctrl-C to end
At time 0.00 s: multiple syncs detected, last 95 ms ago
At time 0.10 s: multiple syncs detected, last 96 ms ago
```

プログラムは [answers/04-sync_timing.rb](answers/04-sync_timing.rb):

```ruby
require "rbbcc"
include RbBCC

# load BPF program
b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
BPF

b.attach_kprobe(event: b.get_syscall_fnname("sync"), fn_name: "do_trace")
puts("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
b.trace_fields do |task, pid, cpu, flags, ts, ms|
  start = ts.to_f if start.zero?
  ts = ts.to_f - start
  puts("At time %.2f s: multiple syncs detected, last %s ms ago" % [ts, ms.chomp])
end
```

この回の学びです(全部 C の話です):

1. ```bpf_ktime_get_ns()```: 今のカーネル内時間をナノ秒の解像度で返します。
1. ```BPF_HASH(last)```: BPF map を、Hash（連想配列）オブジェクトとして作成します。 ```"last"``` という名前です。今回は追加の引数を指定しませんので、 u64 型のkeyとvalueで定義されます。
1. ```key = 0```: このkey/valueストアには一つのペアしか登録しません。なので `0` でハードコーディングします。
1. ```last.lookup(&key)```: Hashからkeyを探し、存在したらvalueへのポインタを、なければ `NULL` を返します。keyもポインタとして渡してください。
1. ```last.delete(&key)```: Hashから指定したkeyを削除します。現在は [カーネルの `.update()` のバグがあるので](https://git.kernel.org/cgit/linux/kernel/git/davem/net.git/commit/?id=a6ed3ea65d9868fdf9eff84e6fe4f666b8d14b02) 、念のため必要です。
1. ```last.update(&key, &ts)```: keyと2番目の引数のvalueを関連づけ、それまでのvalueを上書きします。このレコードはタイムスタンプですね。

*Note for RbBCC developers:* `trace_fields` メソッドの返り値がPython版と微妙に違うので直した方がいいです。

### Lesson 5. sync_count.rb

先ほどのレッスンの sync_timing.rb を変更し、すべての sync システムコールの呼び出し回数を保存するようにしましょう（早い遅いに関わらず）。そして出力しましょう。このカウントアップはBPFプログラムの中で、いまあるHashに新しいキーを導入することで記録できるでしょう。

回答例の一つは [answers/05-sync_count.rb](answers/05-sync_count.rb) です。

### Lesson 6. disksnoop.rb

[answers/06-disksnoop.rb](answers/06-disksnoop.rb) を見てみましょう。これがサンプル出力です:

```
# bundle exec answers/06-disksnoop.rb
TIME(s)            T  BYTES    LAT(ms)
16458043.436012    W  4096        3.13
16458043.437326    W  4096        4.44
16458044.126545    R  4096       42.82
16458044.129872    R  4096        3.24
[...]
```

コードスニペットです:

```ruby
require 'rbbcc'
include RbBCC

REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BCC.new(text: <<CLANG)
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
  // stash start timestamp by request ptr
  u64 ts = bpf_ktime_get_ns();

  start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
  u64 *tsp, delta;

  tsp = start.lookup(&req);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    bpf_trace_printk("%d %x %d\\n", req->__data_len,
        req->cmd_flags, delta / 1000);
    start.delete(&req);
  }
}
CLANG

b.attach_kprobe(event: "blk_start_request", fn_name: "trace_start")
b.attach_kprobe(event: "blk_mq_start_request", fn_name: "trace_start")
b.attach_kprobe(event: "blk_account_io_completion", fn_name: "trace_completion")
[...]
```

今回の学習内容です:

1. ```REQ_WRITE```: カーネル関数をRubyのプログラムの中で定義し、後ろで利用しています。BPFのプログラムの中で REQ_WRITE 定数を使う場合、 `#include` で適切なヘッダを読み込むことで、自分で定義しなくても動作するでしょう。
1. ```trace_start(struct pt_regs *ctx, struct request *req)```: この関数はあとでkprobeにアタッチします。このkprobe用の関数の最初の引数は ```struct pt_regs *ctx``` で、BPFのコンテクストを表します。第2引数以降で実際のカーネル関数の引数を列挙します。今回はこれを blk_start_request() に割り当てる予定で、これの最初の引数の型は ```struct request *``` です。
1. ```start.update(&req, &ts)```: ```struct request``` へのポインタをHashのkeyに使っています。どういうことか？ トレーシングでよく使う技です。構造体のポインタはkeyとしてふさわしいもので、なぜならその値はユニークだからです: 2つの構造体は同じポインタアドレスを持たないため。(freeされてアドレスが再利用される場合にだけは注意しましょう。)なので、私たちがここでしたいのは単にリクエストにタグを打ちたいだけで、それぞれのリクエストはdisk I/Oの詳細を記述しており、それごとにタイムスタンプを発行することで間隔を計測します。ちなみにタイムスタンプを格納する上では2つのkeyが使えます: 構造体のポインタと、Thread ID(特に、関数の開始とreturnまでを計測する場合)です。
1. ```req->__data_len```: ```struct request```のメンバをデリファレンスしています。カーネルのソースコードを見てメンバが何か確認しましょう。 bcc は実際にはこれらの表現は ```bpf_probe_read()``` の呼び出しに置換しています。時として、複雑なデリファレンスには対応できないので、 ```bpf_probe_read()``` を直接呼び必要があるでしょう。

これは大変面白いプログラムで、このコードの理解ができたのなら、多くの重要な基本を理解したと言えるでしょう。なお、いまだに bpf_trace_printk() を利用していますので、次でそれを修正しましょう。

### Lesson 7. hello_perf_output.rb

いよいよ、 `bpf_trace_printk()` の利用をやめ、適切な `BPF_PERF_OUTPUT()` インタフェースを使うようにしましょう。これは、 `trace_field()` がデフォルトで付与してくれるPIDやタイムスタンプなどの情報を自分で直接取得することを意味します。これが別のターミナルでコマンドを実行しながらのサンプルのアウトプットです。

```
# bundle exec answers/07-hello_perf_output.rb
TIME(s)            COMM             PID    MESSAGE
0.000000000        bash             22986  Hello, perf_output!
0.021080275        systemd-udevd    484    Hello, perf_output!
0.021359520        systemd-udevd    484    Hello, perf_output!
0.021590610        systemd-udevd    484    Hello, perf_output!
[...]
```

コードは [answers/07-hello_perf_output.rb](answers/07-hello_perf_output.rb) です:

```ruby
#!/usr/bin/env ruby
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.
# Ported from hello_perf_output.py

require 'rbbcc'
include RbBCC

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BCC.new(text: prog)
b.attach_kprobe(event: b.get_syscall_fnname("clone"), fn_name: "hello")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "MESSAGE"])

# process event
start = 0
print_event = lambda { |cpu, data, size|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  puts("%-18.9f %-16s %-6d %s" % [time_s, event.comm, event.pid,
                                  "Hello, perf_output!"])
}

# loop with callback to print_event
b["events"].open_perf_buffer(&print_event)

loop do
  b.perf_buffer_poll()
end
```

学ぶべきこと:

1. ```struct data_t```: これは、カーネルからユーザースペースに渡すデータの構造を宣言しています。
1. ```BPF_PERF_OUTPUT(events)```: 私たちが今から使うチャンネルを "events" と名付けています。
1. ```struct data_t data = {};```: 空の `data_t` 構造体を作成し、その後中身を埋めます。
1. ```bpf_get_current_pid_tgid()```: 下位の32bitで、「プロセスID/PID」を返します(カーネルから見たPIDです。ユーザスペースからは、一般にスレッドIDと呼ばれます)。そしてスレッドグループID/TGIDは上位32bitに含まれています(これは、ユーザスペースで言うところのPIDです)。この関数を返り値をu32型の変数に格納すると、上位の32bit分は破棄されます。PIDとTGIDのどちらを利用すべきでしょうか？ マルチスレッドなアプリケーションでは、どのスレッドもTGIDは同じはずです。したがってもし必要であればPIDで区別する必要があります。そしてこれはツールのエンドユーザーが予期しているところでもあるでしょう。
1. ```bpf_get_current_comm()```: 最初の引数のポインタアドレスに現在のプロセス名を格納します。
1. ```events.perf_submit()```: ここで、perfのリングバッファを経由して、イベントをユーザスペースに送信します。
1. ```print_event = lambda { ... }```: ```events``` ストリームから流れてくるイベントをハンドルするRubyのprocオブジェクト(lamnbda)を定義します; ところでPythonと違い、Ruby版の `Table#open_perf_buffer` は直接ブロックを受け取ることもできます :)
1. ```b["events"].event(data)```: ここで、Cの定義から自動生成したRubyのオブジェクトとして、イベントデータを受け取ります。
1. ```b["events"].open_perf_buffer(&print_event)```: proc ```print_event``` をCで定義した ```events``` と関連づけます。
1. ```loop { b.perf_buffer_poll() }```: イベントが来るのを待ち構えます。

### Lesson 8. sync_perf_output.rb

前のレッスンのsync_timing.rbを、 ```BPF_PERF_OUTPUT``` を使うよう書き換えてください。

回答例はこちら: [answers/08-sync_perf_output.rb](answers/08-sync_perf_output.rb).

### Lesson 9. bitehist.rb

次のツールは、disk I/Oのサイズを記録しヒストグラムで可視化します。サンプル出力です:

```
# bundle exec answers/09-bitehist.rb
Tracing... Hit Ctrl-C to end.
^C
     kbytes          : count     distribution
       0 -> 1        : 3        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 211      |**********                            |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 800      |**************************************|
```

コードは [answers/09-bitehist.rb](answers/09-bitehist.rb) です:

```ruby
require 'rbbcc'
include RbBCC

# load BPF program
b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, struct request *req)
{
	dist.increment(bpf_log2l(req->__data_len / 1024));
	return 0;
}
BPF

# header
puts("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
begin
  loop { sleep 0.1 }
rescue Interrupt
  puts
end

# output
b["dist"].print_log2_hist("kbytes")
```

ここまでのレッスンのおさらい:

- ```kprobe__```: このプレフィックスにより、その後ろの名前のカーネル関数をkprobeでの計測対象にすることを意味します。
- ```struct pt_regs *ctx, struct request *req```: kprobeへの引数です。 ```ctx``` でBPFのコンテクストを取得し、 ```req``` は計測対象の関数 ```blk_account_io_completion()``` の最初の引数です。
- ```req->__data_len```: その `req` のメンバをデリファレンスします。

新しい要素です:

1. ```BPF_HISTOGRAM(dist)```: ヒストグラムのためのBPF mapオブジェクトを定義し、 "dist" と名付けます。
1. ```dist.increment()```: 第1引数で指定されたインデックスのヒストグラム上の階級を1つインクリメントします。オプションとして。第2引数にインクリメントする度合いを指定することもできます。
1. ```bpf_log2l()```: 引数の値の log2() を計算し返します。これがヒストグラムのインデックスになるので、2のべき乗のヒストグラムを作成することになります。
1. ```b["dist"].print_log2_hist("kbytes")```: "dist" に加工のしたヒストグラムを、 "kbytes" と言うヘッダで出力します。カーネルからユーザスペースへ送信されるデータは各階級のカウントだけになるので、効率的です。

### Lesson 10. disklatency.rb

disk I/O のレイテンシを計測し、ヒストグラムを出力するプログラムを書きましょう。disk I/Oのトレースと時間計測は以前書いたdisksnoop.rbで、ヒストグラムの作り方はさきほどのbitehist.rbを参考にできます。

回答例は: [answers/10-disklatency.rb](answers/10-disklatency.rb).

### Lesson 11. vfsreadlat.rb

このサンプルはRubyとCのファイルに分かれています。出力例です:

```
# bundle exec answers/11-vfsreadlat.rb 1
Tracing... Hit Ctrl-C to end.
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 2        |***********                             |
         4 -> 7          : 7        |****************************************|
         8 -> 15         : 4        |**********************                  |

     usecs               : count     distribution
         0 -> 1          : 29       |****************************************|
         2 -> 3          : 28       |**************************************  |
         4 -> 7          : 4        |*****                                   |
         8 -> 15         : 8        |***********                             |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 2        |**                                      |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 4        |*****                                   |
      8192 -> 16383      : 6        |********                                |
     16384 -> 32767      : 9        |************                            |
     32768 -> 65535      : 6        |********                                |
     65536 -> 131071     : 2        |**                                      |

     usecs               : count     distribution
         0 -> 1          : 11       |****************************************|
         2 -> 3          : 2        |*******                                 |
         4 -> 7          : 10       |************************************    |
         8 -> 15         : 8        |*****************************           |
        16 -> 31         : 1        |***                                     |
        32 -> 63         : 2        |*******                                 |
[...]
```

コードは [answers/11-vfsreadlat.rb](answers/11-vfsreadlat.rb) と [answers/11-vfsreadlat.c](answers/11-vfsreadlat.c) にあるので見てみましょう。学べることは:

1. ```b = BCC.new(src_file: "vfsreadlat.c")```: BPF Cプログラムを別の場所から読み込みます。Rubyファイルと同じディレクトリにあればOKです。
1. ```b.attach_kretprobe(event: "vfs_read", fn_name: "do_return")```: BPFのC関数 ```do_return()``` をカーネル関数 ```vfs_read()``` にアタッチします。これは kretprobe と呼ばれるもので、いままでのように関数のエントリーではなく、関数のreturnを計測するものです。
1. ```b["dist"].clear()```: ヒストグラムをRuby側からクリアします。定期的なインターバルで計測するためです。

### Lesson 12. urandomread.rb

```dd if=/dev/urandom of=/dev/null bs=8k count=5``` の実行をトレースします:

```
# bundle exec answers/12-urandomread.rb
TIME(s)            COMM             PID    GOTBITS
24652832.956994001 smtp             24690  384
24652837.726500999 dd               24692  65536
24652837.727111001 dd               24692  65536
24652837.727703001 dd               24692  65536
24652837.728294998 dd               24692  65536
24652837.728888001 dd               24692  65536
```

おや！偶然smtpのイベントも捕まえました。コードは [answers/12-urandomread.rb](answers/12-urandomread.rb):

```ruby
require 'rbbcc'
include RbBCC

b = BCC.new(text: <<BPF)
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
BPF

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "GOTBITS"])

# format output
loop do
  begin
    b.trace_fields do |task, pid, cpu, flags, ts, msg|
      puts("%-18.9f %-16s %-6d %s" % [ts, task, pid, msg])
    end
  rescue Interrupt
    exit
  end
end
```

学ぶことです:

1. ```TRACEPOINT_PROBE(random, urandom_read)```: カーネルの tracepoint(Rubyの `TracePoint` クラスとは名前が同じだけです)である ```random:urandom_read``` を計測します。このtracepointは「安定した(stable)」APIを提供します。カーネル関数のようにバージョンによって変わることがないと言う意味です。そのため、可能な限りkprobeよりもこちらを使うことが推奨されます。 ```perf list``` コマンドを実行すればtracepointのリストが手に入ります。BPFのプログラムをtracepointにアタッチするにはLinuxのバージョン4.7以上が必要です。
1. ```args->got_bits```: ```args``` はTRACEPOINT_PROBEマクロが自動定義する変数で、tracepointの引数が格納された構造体です。上にあるコメントはその構造を確認できるLinux上のファイルです。例えば:

```
# cat /sys/kernel/debug/tracing/events/random/urandom_read/format
name: urandom_read
ID: 972
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int got_bits;	offset:8;	size:4;	signed:1;
	field:int pool_left;	offset:12;	size:4;	signed:1;
	field:int input_left;	offset:16;	size:4;	signed:1;

print fmt: "got_bits %d nonblocking_pool_entropy_left %d input_entropy_left %d", REC->got_bits, REC->pool_left, REC->input_left
```

今回は、 ```got_bits``` メンバを表示しています。

### Lesson 13. disksnoop.rb fixed

ここまでのレッスンで作成した disksnoop.rb を、 ```block:block_rq_issue``` と ```block:block_rq_complete``` tracepointを使って書き直しましょう。

たとえば、回答例は [answers/13-disksnoop_fixed.rb](answers/13-disksnoop_fixed.rb) です。


### Lesson 14. strlen_count.rb

このプログラムは（カーネルではなく）ユーザレベルの関数をトレースします。今回はライブラリ関数 ```strlen()``` で、その引数の文字列の登場回数をカウントします。こう言う出力です:

```
# bundle exec answers/14-strlen_count.rb
Tracing strlen()... Hit Ctrl-C to end.
^C     COUNT STRING
         1 " "
         1 "/bin/ls"
         1 "."
         1 "cpudist.py.1"
         1 ".bashrc"
         1 "ls --color=auto"
         1 "key_t"
[...]
        10 "a7:~# "
        10 "/root"
        12 "LC_ALL"
        12 "en_US.UTF-8"
        13 "en_US.UTF-8"
        20 "~"
        70 "#%^,~:-=?+/}"
       340 "\x01\x1b]0;root@bgregg-test: ~\x07\x02root@bgregg-test:~# "
```

このライブラリ関数で処理される文字列には様々な種類があることが、登場回数のカウントからわかります。たとえば "LC_ALL" と言う文字列は12回 ```strlen()``` の引数になりました。

コードは [answers/14-strlen_count.rb](answers/14-strlen_count.rb):

```ruby
require 'rbbcc'
include RbBCC

# load BPF program
b = BCC.new(text: <<BPF)
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
BPF
b.attach_uprobe(name: "c", sym: "strlen", fn_name: "count")

# header
print("Tracing strlen()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
begin
  sleep(99999999)
rescue Interrupt
  puts
end

# print output
puts("%10s %s" % ["COUNT", "STRING"])
counts = b.get_table("counts")
counts.items.sort_by{|k, v| v.to_bcc_value }.each do |k, v|
  # unpack following definition of struct key_t above
  puts("%10d %s" % [v.to_bcc_value, k[0, k.size].unpack("Z*")[0]])
end
```

今回の学びです:

1. ```PT_REGS_PARM1(ctx)```: ```strlen()``` の最初の引数をレジスタから取り出します。文字列です。
1. ```b.attach_uprobe(name: "c", sym: "strlen", fn_name: "count")```: "c" ライブラリ(もし関数がプログラムの側にあるのなら、バイナリのpathnameを用いてください)にアタッチし、ユーザレベル関数 ```strlen()``` を計測、その実行のたびに私たちが定義したC関数 ```count()``` を呼び出します。
1. ```BPF_HASH``` から `Table#items` で取り出した値をRubyで扱うには、面倒ですが ```k/v.to_bcc_value``` をRubyのブロックの中などで呼び出す必要があります。この挙動はRuby版の実装の都合によるものですが、将来変更する可能性があります。

### Lesson 15. nodejs_http_server.rb

このプログラムはユーザが静的に定義したトレースポイント(User Statically-Defined Tracing: **USDT**)をprobeとして計測するもので、USDTはユーザランドにおけるカーネルのtracepointに相当するものです。出力例です:

```
# bundle exec answers/15-nodejs_http_server.rb
TIME(s)            COMM             PID    ARGS
24653324.561322998 node             24728  path:/index.html
24653335.343401998 node             24728  path:/images/welcome.png
24653340.510164998 node             24728  path:/images/favicon.png
```

回答例は [answers/15-nodejs_http_server.rb](answers/15-nodejs_http_server.rb) にあります; 同じディレクトリにあるnode.jsのサーバプログラムを、USDTを有効にした(`--enable-dtrace`)ビルドのnode.jsバイナリで実行して計測する必要があります。

```ruby
require 'rbbcc'
include RbBCC

if ARGV.size != 1 :
  print("USAGE: #{$0} PID")
  exit()
end
pid = ARGV[0]
debug = !!ENV['DEBUG']

# load BPF program
bpf_text = <<BPF
#include <uapi/linux/ptrace.h>
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128]={0};
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
BPF

# enable USDT probe from given PID
u = USDT.new(pid: pid.to_i)
u.enable_probe(probe: "http__server__request", fn_name: "do_trace")
if debug
  puts(u.get_text)
  puts(bpf_text)
end

# initialize BPF
b = BCC.new(text: bpf_text, usdt_contexts: [u])
```

今回の学び:

1. ```bpf_usdt_readarg(6, ctx, &addr)```: USDT probeの6番目の引数が格納されたアドレスを、 ```addr``` に読み込みます。
1. ```bpf_probe_read(&path, sizeof(path), (void *)addr)```: ここで、 ```addr``` が示している文字列をBPFプログラム側の ```path``` に格納します。
1. ```u = USDT.new(pid: pid.to_i)```: USDTのトレースを与えられたPIDに対してできるよう初期化します。
1. ```u.enable_probe(probe: "http__server__request", fn_name: "do_trace")```: 私たちの書いたBPF C関数 ```do_trace()``` をNode.jsのUSDTである ```http__server__request``` probeにアタッチします。
1. ```b = BCC.new(text: bpf_text, usdt_contexts: [u])```: BPFのオブジェクトを作る際に、先ほどのUSDTオブジェクト ```u``` を渡す必要があります。

もちろん、Ruby自身にもUSDTが存在するので、このレッスンでサンプルを追加する予定です(P/Rは歓迎です)。

### Lesson 16. task_switch.c

This is an older tutorial included as a bonus lesson. Use this for recap and to reinforce what you've already learned.

This is a slightly more complex tracing example than Hello World. This program
will be invoked for every task change in the kernel, and record in a BPF map
the new and old pids.

The C program below introduces a new concept: the prev argument. This
argument is treated specially by the BCC frontend, such that accesses
to this variable are read from the saved context that is passed by the
kprobe infrastructure. The prototype of the args starting from
position 1 should match the prototype of the kernel function being
kprobed. If done so, the program will have seamless access to the
function parameters.

```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 prev_pid;
    u32 curr_pid;
};

BPF_HASH(stats, struct key_t, u64, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.curr_pid = bpf_get_current_pid_tgid();
    key.prev_pid = prev->pid;

    // could also use `stats.increment(key);`
    val = stats.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
}
```

The userspace component loads the file shown above, and attaches it to the
`finish_task_switch` kernel function.
The `[]` operator of the BPF object gives access to each BPF_HASH in the
program, allowing pass-through access to the values residing in the kernel. Use
the object as you would any other python dict object: read, update, and deletes
are all allowed.

```ruby
require 'rbbcc'
include RbBCC

b = BCC.new(src_file: "16-task_switch.c")
b.attach_kprobe(event: "finish_task_switch", fn_name: "count_sched")

# generate many schedule events
100.times { sleep 0.01 }

b["stats"].each do |_k, v|
  k = _k[0, 8].unpack("i! i!") # Handling pointer without type!!
  puts("task_switch[%5d->%5d]=%u" % [k[0], k[1], v.to_bcc_value])
end
```

These programs can be found in the files [answers/16-task_switch.c](answers/16-task_switch.c) and [answers/16-task_switch.rb](answers/16-task_switch.rb) respectively.

### Lesson 17. Further Study

For further study, see [BCC original docs](https://github.com/iovisor/bcc/tree/master/docs) and Sasha Goldshtein's [linux-tracing-workshop](https://github.com/goldshtn/linux-tracing-workshop), which contains additional labs. There are also many tools in rbbcc/bcc /tools to study.

Please read [CONTRIBUTING-SCRIPTS.md](../CONTRIBUTING-SCRIPTS.md) if you wish to contrubite tools to rbbcc. At the bottom of the main [README.md](../README.md), you'll also find methods for contacting us. Good luck, and happy tracing!

---

## Networking

To do.
