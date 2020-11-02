using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Blueject
{
    class Program
    {
        static void Main(string[] args)
        {
            Process p = Process.GetProcessesByName("csgo")[0];

            BInjector Injector = new BInjector();
            Injector.Inject(p, "Bluehack.dll");
        }
    }
}
